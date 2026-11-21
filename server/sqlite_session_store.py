"""Durable synthetic bearer-session storage; NOT the AOW APK login protocol.

Only a SHA-256 digest of each high-entropy server-issued token is persisted.
Callers must authenticate an account before issue() and authorize ownership on
every state-changing operation. This module does not verify passwords, parse
packets, or make any APK compatibility claim.
"""
from contextlib import contextmanager
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
        if type(connection) is not sqlite3.Connection:
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self._validate_ttl(ttl_seconds)
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self.db = connection
        self.ttl_seconds = ttl_seconds
        self.clock = clock if clock is not None else time.time
        self.db.execute("PRAGMA busy_timeout = 10000")
        existing = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name='durable_sessions'"
        ).fetchone()
        if existing == ("table",):
            # The common, already-initialized path is read-only. Do not acquire
            # SQLite's write reservation merely to validate a usable store:
            # authorized state transactions on other connections must not be
            # delayed by constructing another store instance.
            if self._validate_schema(create_missing_index=False):
                return
        elif existing is not None:
            raise ValueError("incompatible durable session table")

        # Only missing DDL is created under a write reservation. Re-check the
        # complete schema after acquiring it because another process may have
        # initialized the store since the initial read.
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS durable_sessions (
                    token_hash BLOB PRIMARY KEY
                        CHECK(typeof(token_hash) = 'blob' AND length(token_hash) = 32),
                    account_id INTEGER NOT NULL CHECK(account_id > 0),
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL CHECK(expires_at > created_at)
                )"""
            )
            self._validate_schema()
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _validate_schema(self, *, create_missing_index=True):
        """Reject an incompatible pre-existing session table or expiry index."""
        table = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name='durable_sessions'"
        ).fetchone()
        if table != ("table",):
            raise ValueError("incompatible durable session table")

        expected_columns = {
            "token_hash": ("BLOB", 0, 1, None),
            "account_id": ("INTEGER", 1, 0, None),
            "created_at": ("REAL", 1, 0, None),
            "expires_at": ("REAL", 1, 0, None),
        }
        rows = self.db.execute(
            "PRAGMA table_info(durable_sessions)"
        ).fetchall()
        actual_columns = {
            row[1]: (
                str(row[2]).strip().upper(),
                int(row[3]),
                int(row[5]),
                row[4],
            )
            for row in rows
        }
        if len(rows) != len(expected_columns) or actual_columns != expected_columns:
            raise ValueError("incompatible durable session schema")

        index_object = self.db.execute(
            "SELECT type, tbl_name FROM sqlite_master "
            "WHERE name='durable_sessions_expiry'"
        ).fetchone()
        if index_object is None:
            if not create_missing_index:
                return False
            self.db.execute(
                "CREATE INDEX durable_sessions_expiry "
                "ON durable_sessions(expires_at)"
            )
            return True
        if index_object != ("index", "durable_sessions"):
            raise ValueError("incompatible durable session expiry index")

        indexes = [
            row for row in self.db.execute(
                "PRAGMA index_list(durable_sessions)"
            ).fetchall()
            if row[1] == "durable_sessions_expiry"
        ]
        if (len(indexes) != 1 or int(indexes[0][2]) != 0
                or (len(indexes[0]) > 4 and int(indexes[0][4]) != 0)):
            raise ValueError("incompatible durable session expiry index")
        indexed_columns = tuple(
            row[2] for row in self.db.execute(
                "PRAGMA index_info(durable_sessions_expiry)"
            ).fetchall()
        )
        if indexed_columns != ("expires_at",):
            raise ValueError("incompatible durable session expiry index")
        return True

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

    def _require_idle_connection(self):
        """Reject operations that own their transaction on a caller transaction."""
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")

    def _now(self):
        try:
            value = self.clock()
        except Exception as exc:
            raise ValueError("session clock failed") from None
        # Accept only exact built-in numeric values. Numeric subclasses can
        # override __float__ and execute caller code during expiry validation.
        if type(value) not in (int, float):
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
        if type(token) is not str or not _TOKEN_PATTERN.fullmatch(token):
            raise SessionError("invalid session")
        return hashlib.sha256(token.encode("ascii")).digest()

    @staticmethod
    def _validated_stored_session_row(row, now=None):
        """Reject corrupt or not-yet-valid persisted sessions without coercion."""
        if row is None:
            return None
        account_id, created_at, expires_at = row
        if (type(account_id) is not int
                or not 1 <= account_id <= _MAX_ACCOUNT_ID):
            raise SessionError("invalid session")
        if type(created_at) not in (int, float) or type(expires_at) not in (int, float):
            raise SessionError("invalid session")
        try:
            created = float(created_at)
            expiry = float(expires_at)
            latest_expiry = created + _MAX_TTL_SECONDS
        except (OverflowError, ValueError):
            raise SessionError("invalid session") from None
        if (not math.isfinite(created) or created < 0
                or not math.isfinite(expiry) or expiry <= created
                or not math.isfinite(latest_expiry) or latest_expiry <= created
                or expiry > latest_expiry
                or (now is not None and created > now)):
            raise SessionError("invalid session")
        return account_id, expiry

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
        self._require_idle_connection()
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
        self._require_idle_connection()
        digest = self._digest(token)
        self.db.execute("BEGIN IMMEDIATE")
        account_id = None
        expired = False
        try:
            now = self._now()
            row = self.db.execute(
                "SELECT account_id, created_at, expires_at "
                "FROM durable_sessions WHERE token_hash=?",
                (digest,),
            ).fetchone()
            if row is not None:
                stored_account_id, expires_at = self._validated_stored_session_row(row, now)
                if now >= expires_at:
                    self.db.execute(
                        "DELETE FROM durable_sessions WHERE token_hash=?", (digest,)
                    )
                    expired = True
                else:
                    account_id = stored_account_id
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

        if expired:
            raise SessionError("expired session")
        if account_id is None:
            raise SessionError("invalid session")
        return account_id

    def _resolve_digest_in_transaction(self, digest: bytes) -> int:
        """Resolve a token digest while the caller owns an SQLite transaction."""
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        now = self._now()
        row = self.db.execute(
            "SELECT account_id, created_at, expires_at "
            "FROM durable_sessions WHERE token_hash=?",
            (digest,),
        ).fetchone()
        if row is None:
            raise SessionError("invalid session")
        account_id, expires_at = self._validated_stored_session_row(row, now)
        if now >= expires_at:
            raise SessionError("expired session")
        return account_id

    def resolve_in_transaction(self, token: str) -> int:
        """Resolve an active token without opening or committing a transaction.

        The caller must hold a transaction (preferably BEGIN IMMEDIATE) across
        both this check and the protected state read/write. This makes session
        revocation serialize with the protected operation.
        """
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        return self._resolve_digest_in_transaction(self._digest(token))

    @contextmanager
    def authorized_transaction(self, token: str):
        """Hold a write transaction while resolving a token and changing state.

        The context commits when the protected operation succeeds and rolls
        back when it raises. The yielded account id is resolved only after
        BEGIN IMMEDIATE acquires SQLite's write reservation, so revocation
        cannot interleave between authorization and the caller's database work.
        The caller must not commit or roll back the connection inside the block.
        """
        self._require_idle_connection()
        digest = self._digest(token)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            account_id = self._resolve_digest_in_transaction(digest)
            yield account_id
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def revoke(self, token: str) -> bool:
        """Revoke a token. Repeating the same revocation returns False."""
        self._require_idle_connection()
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

    def revoke_all_for_account(self, account_id: int) -> int:
        """Revoke every session for one account and return the number removed.

        This is the synthetic server-side equivalent of logging out all devices.
        It removes active and expired rows alike. BEGIN IMMEDIATE serializes the
        revocation with authorized_transaction() on other SQLite connections.
        """
        self._require_idle_connection()
        if (type(account_id) is not int
                or not 1 <= account_id <= _MAX_ACCOUNT_ID):
            raise ValueError("invalid account id")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            result = self.db.execute(
                "DELETE FROM durable_sessions WHERE account_id=?", (account_id,)
            )
            self.db.commit()
            return result.rowcount
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

        self._require_idle_connection()
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


    def verify_integrity(self) -> dict:
        """Audit persisted sessions in one consistent, read-only snapshot.

        The connection must be idle. The audit pins a SQLite read snapshot,
        runs quick_check, and streams every row through the same strict
        account/expiry validator used by token resolution. It never deletes
        expired rows or repairs data. The report separates active and expired
        rows at one captured clock value; cleanup remains a separate operation.
        """
        self._require_idle_connection()
        self.db.execute("BEGIN")
        try:
            # Establish the read snapshot before quick_check and row scanning.
            self.db.execute(
                "SELECT name FROM sqlite_master LIMIT 1"
            ).fetchone()
            if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise SessionError("invalid session store")

            duplicate_digest = self.db.execute(
                "SELECT 1 FROM durable_sessions "
                "GROUP BY token_hash HAVING COUNT(*) > 1 LIMIT 1"
            ).fetchone()
            if duplicate_digest is not None:
                raise SessionError("invalid session store")

            now = self._now()
            session_count = 0
            active_session_count = 0
            expired_session_count = 0
            rows = self.db.execute(
                "SELECT token_hash, account_id, created_at, expires_at "
                "FROM durable_sessions"
            )
            for token_hash, account_id, created_at, expires_at in rows:
                if type(token_hash) is not bytes or len(token_hash) != 32:
                    raise SessionError("invalid session store")
                _validated_account_id, validated_expiry = (
                    self._validated_stored_session_row(
                        (account_id, created_at, expires_at), now
                    )
                )
                session_count += 1
                if now >= validated_expiry:
                    expired_session_count += 1
                else:
                    active_session_count += 1
            return {
                "session_count": session_count,
                "active_session_count": active_session_count,
                "expired_session_count": expired_session_count,
            }
        finally:
            if self.db.in_transaction:
                self.db.rollback()


    def rotate_in_transaction(self, token: str, ttl_seconds=None) -> str:
        """Atomically replace an active token inside the caller's transaction.

        A SAVEPOINT makes the two-row transition locally atomic even when the
        caller catches an error and later commits its surrounding transaction.
        The caller still owns the outer commit/rollback boundary.
        """
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        digest = self._digest(token)
        ttl = self.ttl_seconds if ttl_seconds is None else ttl_seconds
        self._validate_ttl(ttl)

        self.db.execute("SAVEPOINT durable_session_rotation")
        try:
            now = self._now()
            row = self.db.execute(
                "SELECT account_id, created_at, expires_at "
                "FROM durable_sessions WHERE token_hash=?",
                (digest,),
            ).fetchone()
            if row is None:
                raise SessionError("invalid session")
            account_id, expires_at = self._validated_stored_session_row(row, now)
            if now >= expires_at:
                raise SessionError("expired session")

            replacement_token = secrets.token_urlsafe(32)
            replacement_digest = self._digest(replacement_token)
            replacement_expiry = now + ttl
            if (not math.isfinite(replacement_expiry)
                    or replacement_expiry <= now):
                raise ValueError(
                    "clock cannot represent the requested session expiry"
                )

            self.db.execute(
                "INSERT INTO durable_sessions "
                "(token_hash, account_id, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (replacement_digest, account_id, now, replacement_expiry),
            )
            deleted = self.db.execute(
                "DELETE FROM durable_sessions WHERE token_hash=?",
                (digest,),
            )
            if deleted.rowcount != 1:
                raise SessionError("invalid session")
            self.db.execute("RELEASE SAVEPOINT durable_session_rotation")
            return replacement_token
        except BaseException:
            self.db.execute("ROLLBACK TO SAVEPOINT durable_session_rotation")
            self.db.execute("RELEASE SAVEPOINT durable_session_rotation")
            raise

    def rotate(self, token: str, ttl_seconds=None) -> str:
        """Rotate a bearer token and commit replacement/revocation atomically.

        Concurrent attempts to rotate the same token serialize under
        BEGIN IMMEDIATE; only the first can replace the active digest.
        """
        self._require_idle_connection()
        self.db.execute("BEGIN IMMEDIATE")
        try:
            replacement = self.rotate_in_transaction(token, ttl_seconds)
            self.db.commit()
            return replacement
        except BaseException:
            self.db.rollback()
            raise
