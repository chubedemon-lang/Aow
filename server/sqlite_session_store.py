"""Durable synthetic bearer-session storage; NOT the AOW APK login protocol.

Only a SHA-256 digest of each high-entropy server-issued token is persisted.
Callers must authenticate an account before issue() and authorize ownership on
every state-changing operation. This module does not verify passwords, parse
packets, or make any APK compatibility claim.
"""
import hashlib
import math
import re
import secrets
import sqlite3
import time

from server.sessions import SessionError


_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_TTL_SECONDS = 31_536_000
_MAX_ACCOUNT_ID = 2**63 - 1
_MAX_PURGE_BATCH_SIZE = 10_000


class SqliteSessionStore:
    """Persist opaque synthetic sessions in an existing SQLite connection.

    The connection must not already be inside a transaction when a public
    operation is called. Use an epoch-based clock (time.time by default), not
    time.monotonic, because expiry timestamps survive process restarts.
    """

    def __init__(self, connection: sqlite3.Connection, ttl_seconds: int = 900,
                 clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self._validate_ttl(ttl_seconds)
        self.db = connection
        self.ttl_seconds = ttl_seconds
        self.clock = clock if clock is not None else time.time
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS durable_sessions (
                token_hash BLOB PRIMARY KEY
                    CHECK(typeof(token_hash) = 'blob' AND length(token_hash) = 32),
                account_id INTEGER NOT NULL CHECK(account_id > 0),
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL CHECK(expires_at > created_at)
            )"""
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS durable_sessions_expiry "
            "ON durable_sessions(expires_at)"
        )
        self.db.commit()

    @staticmethod
    def _validate_ttl(ttl_seconds):
        if (type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS):
            raise ValueError("invalid session ttl")

    @staticmethod
    def _validate_purge_batch_size(batch_size):
        if (type(batch_size) is not int
                or not 1 <= batch_size <= _MAX_PURGE_BATCH_SIZE):
            raise ValueError("invalid session purge batch size")

    def _now(self):
        value = self.clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("clock must return a finite non-negative epoch time")
        try:
            numeric = float(value)
        except (OverflowError, ValueError):
            raise ValueError("clock must return a finite non-negative epoch time") from None
        if not math.isfinite(numeric) or numeric < 0:
            raise ValueError("clock must return a finite non-negative epoch time")
        return numeric

    @staticmethod
    def _digest(token):
        if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
            raise SessionError("invalid session")
        return hashlib.sha256(token.encode("ascii")).digest()

    def issue_in_transaction(self, account_id: int, ttl_seconds=None) -> str:
        """Insert a session without opening or committing the caller's transaction.

        The caller must hold a transaction across the authentication decision
        and this insert. Prefer BEGIN IMMEDIATE so credential changes and
        session issuance serialize. The caller owns commit/rollback.
        """
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        if (type(account_id) is not int
                or not 1 <= account_id <= _MAX_ACCOUNT_ID):
            raise ValueError("invalid account id")
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        self._validate_ttl(ttl)
        token = secrets.token_urlsafe(32)
        digest = self._digest(token)
        now = self._now()
        expires_at = now + ttl
        if not math.isfinite(expires_at) or expires_at <= now:
            raise ValueError("clock cannot represent the requested session expiry")
        self.db.execute(
            "INSERT INTO durable_sessions "
            "(token_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (digest, account_id, now, expires_at),
        )
        return token

    def issue(self, account_id: int, ttl_seconds=None) -> str:
        """Issue a random bearer token after trusted account authentication."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            token = self.issue_in_transaction(account_id, ttl_seconds)
            self.db.commit()
            return token
        except BaseException:
            self.db.rollback()
            raise

    def resolve(self, token: str) -> int:
        """Resolve an active token to its account id; expired rows are removed."""
        digest = self._digest(token)
        self.db.execute("BEGIN IMMEDIATE")
        account_id = None
        expired = False
        try:
            now = self._now()
            row = self.db.execute(
                "SELECT account_id, expires_at FROM durable_sessions WHERE token_hash=?",
                (digest,),
            ).fetchone()
            if row is None:
                pass
            elif now >= float(row[1]):
                self.db.execute(
                    "DELETE FROM durable_sessions WHERE token_hash=?", (digest,)
                )
                expired = True
            else:
                account_id = int(row[0])
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

        if expired:
            raise SessionError("expired session")
        if account_id is None:
            raise SessionError("invalid session")
        return account_id

    def resolve_in_transaction(self, token: str) -> int:
        """Resolve an active token without opening or committing a transaction.

        The caller must hold a transaction (preferably BEGIN IMMEDIATE) across
        both this check and the protected state read/write. This makes session
        revocation serialize with the protected operation.
        """
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        digest = self._digest(token)
        now = self._now()
        row = self.db.execute(
            "SELECT account_id, expires_at FROM durable_sessions WHERE token_hash=?",
            (digest,),
        ).fetchone()
        if row is None:
            raise SessionError("invalid session")
        if now >= float(row[1]):
            raise SessionError("expired session")
        return int(row[0])

    def revoke(self, token: str) -> bool:
        """Revoke a token. Repeating the same revocation returns False."""
        digest = self._digest(token)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            result = self.db.execute(
                "DELETE FROM durable_sessions WHERE token_hash=?", (digest,)
            )
            self.db.commit()
            return result.rowcount == 1
        except BaseException:
            self.db.rollback()
            raise

    def purge_expired(self, batch_size=None) -> int:
        """Delete expired sessions, optionally bounding one cleanup transaction.

        With no batch_size, preserve the original all-at-once behavior. A
        positive batch_size deletes at most that many oldest expired rows,
        ordered by expiry and token digest for deterministic cleanup. Callers
        can repeat bounded batches to avoid holding SQLite's write lock for a
        large cleanup. The method returns the number of rows removed.
        """
        if batch_size is not None:
            self._validate_purge_batch_size(batch_size)

        self.db.execute("BEGIN IMMEDIATE")
        try:
            now = self._now()
            if batch_size is None:
                result = self.db.execute(
                    "DELETE FROM durable_sessions WHERE expires_at <= ?", (now,)
                )
            else:
                result = self.db.execute(
                    """DELETE FROM durable_sessions
                       WHERE token_hash IN (
                           SELECT token_hash FROM durable_sessions
                           WHERE expires_at <= ?
                           ORDER BY expires_at ASC, token_hash ASC
                           LIMIT ?
                       )""",
                    (now, batch_size),
                )
            self.db.commit()
            return result.rowcount
        except BaseException:
            self.db.rollback()
            raise
