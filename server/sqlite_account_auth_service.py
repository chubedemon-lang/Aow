"""Synthetic account credential verification and durable session issuance.

This is a local server-domain foundation only. It does not implement the AOW
APK's login serializer, password format, handshake, transport, or HTTP route.
Enrollment is a trusted operator/setup action; callers must rate-limit failed
authentication attempts before exposing this service through any adapter.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import secrets
import sqlite3

from server.sqlite_session_store import SqliteSessionStore


_MIN_ITERATIONS = 100_000
_MAX_ITERATIONS = 2_000_000
_DEFAULT_ITERATIONS = 600_000
_MAX_TTL_SECONDS = 31_536_000
_MAX_PASSWORD_CHARS = 1024
_MAX_PASSWORD_BYTES = 4096
_MAX_USERNAME_CHARS = 64
_MAX_USERNAME_BYTES = 256
_DUMMY_PASSWORD = b"not-a-real-account-password"


@dataclass(frozen=True)
class AuthenticatedAccountSession:
    """Successful local authentication result; never log or serialize the token."""

    account_id: int
    token: str = field(repr=False)


class AccountAuthError(ValueError):
    """Generic failure returned for unknown accounts and invalid credentials."""


class AccountCredentialAlreadyExists(AccountAuthError):
    """A credential has already been enrolled for this account."""


class SqliteAccountAuthService:
    """Verify synthetic credentials and issue sessions on the same SQLite DB.

    Passwords are stored as PBKDF2-HMAC-SHA256 digests with random salts.
    Verification runs outside the write lock, then rechecks the credential
    under BEGIN IMMEDIATE before issuing a session in that same transaction.
    This avoids holding SQLite's writer lock during the expensive KDF while
    preventing a credential change between verification and session issuance.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 iterations: int = _DEFAULT_ITERATIONS,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        if (type(iterations) is not int
                or not _MIN_ITERATIONS <= iterations <= _MAX_ITERATIONS):
            raise ValueError("PBKDF2 iterations outside supported bounds")
        if (type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS):
            raise ValueError("invalid session ttl")

        try:
            connection.execute("SELECT id, username FROM accounts LIMIT 0")
        except sqlite3.OperationalError as exc:
            raise ValueError(
                "initialized accounts(id, username) table required"
            ) from exc

        self.db = connection
        self.iterations = iterations
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS account_credentials (
                account_id INTEGER PRIMARY KEY CHECK(account_id > 0),
                algorithm TEXT NOT NULL CHECK(algorithm = 'pbkdf2_sha256'),
                iterations INTEGER NOT NULL
                    CHECK(iterations BETWEEN 100000 AND 2000000),
                salt BLOB NOT NULL
                    CHECK(typeof(salt) = 'blob' AND length(salt) = 16),
                password_hash BLOB NOT NULL
                    CHECK(typeof(password_hash) = 'blob' AND length(password_hash) = 32),
                FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
            )"""
        )
        self.db.commit()

        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )

        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_digest = hashlib.pbkdf2_hmac(
            "sha256", _DUMMY_PASSWORD, self._dummy_salt,
            self.iterations, dklen=32,
        )

    @staticmethod
    def _username_is_valid(username):
        if (not isinstance(username, str) or not username
                or len(username) > _MAX_USERNAME_CHARS
                or username != username.strip() or "\x00" in username):
            return False
        try:
            return len(username.encode("utf-8", "strict")) <= _MAX_USERNAME_BYTES
        except UnicodeEncodeError:
            return False

    @staticmethod
    def _password_material(password):
        if not isinstance(password, str) or len(password) > _MAX_PASSWORD_CHARS:
            return b"", False
        try:
            raw = password.encode("utf-8", "strict")
        except UnicodeEncodeError:
            return b"", False
        valid = (
            12 <= len(password) <= _MAX_PASSWORD_CHARS
            and 1 <= len(raw) <= _MAX_PASSWORD_BYTES
        )
        return raw, valid

    def _burn_dummy_kdf(self, password_bytes):
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password_bytes, self._dummy_salt,
            self.iterations, dklen=32,
        )
        hmac.compare_digest(candidate, self._dummy_digest)

    def _lookup_credential(self, username):
        return self.db.execute(
            """SELECT a.id, c.iterations, c.salt, c.password_hash
               FROM accounts AS a
               LEFT JOIN account_credentials AS c ON c.account_id = a.id
               WHERE a.username = ?""",
            (username,),
        ).fetchone()

    def enroll_password(self, account_id: int, password: str) -> None:
        """Enroll one password for an existing account; never overwrite a credential.

        This method is intended for trusted local setup code, not a public
        registration endpoint. Password reset requires a separate verified
        administrative flow and is deliberately not provided here.
        """
        if type(account_id) is not int or account_id < 1:
            raise ValueError("invalid account id")
        password_bytes, valid = self._password_material(password)
        if not valid:
            raise ValueError("password must contain 12..1024 UTF-8 characters")

        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password_bytes, salt, self.iterations, dklen=32
        )
        self.db.execute("BEGIN IMMEDIATE")
        try:
            exists = self.db.execute(
                "SELECT 1 FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if exists is None:
                raise KeyError("account not found")
            try:
                self.db.execute(
                    """INSERT INTO account_credentials
                       (account_id, algorithm, iterations, salt, password_hash)
                       VALUES (?, 'pbkdf2_sha256', ?, ?, ?)""",
                    (account_id, self.iterations, salt, digest),
                )
            except sqlite3.IntegrityError as exc:
                raise AccountCredentialAlreadyExists(
                    "credential already enrolled"
                ) from exc
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def authenticate_and_issue_session(
            self, username: str, password: str) -> AuthenticatedAccountSession:
        """Verify credentials and atomically persist a new opaque session.

        Unknown usernames, accounts without credentials, malformed stored
        records and wrong passwords all produce the same AccountAuthError.
        The session token is returned once and only its SHA-256 digest is
        persisted by SqliteSessionStore.
        """
        password_bytes, password_valid = self._password_material(password)
        if not self._username_is_valid(username):
            self._burn_dummy_kdf(password_bytes)
            raise AccountAuthError("invalid credentials")

        row = self._lookup_credential(username)
        if row is None or row[1] is None:
            self._burn_dummy_kdf(password_bytes)
            raise AccountAuthError("invalid credentials")

        account_id, iterations, salt, stored_digest = row
        if (type(account_id) is not int or not 1 <= account_id <= 2**63 - 1
                or type(iterations) is not int
                or not _MIN_ITERATIONS <= iterations <= _MAX_ITERATIONS
                or not isinstance(salt, (bytes, bytearray, memoryview))
                or len(salt) != 16
                or not isinstance(stored_digest, (bytes, bytearray, memoryview))
                or len(stored_digest) != 32):
            self._burn_dummy_kdf(password_bytes)
            raise AccountAuthError("invalid credentials")

        candidate = hashlib.pbkdf2_hmac(
            "sha256", password_bytes, bytes(salt), iterations, dklen=32
        )
        if not password_valid or not hmac.compare_digest(
                candidate, bytes(stored_digest)):
            raise AccountAuthError("invalid credentials")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            current = self._lookup_credential(username)
            if current != row:
                raise AccountAuthError("invalid credentials")
            token = self.sessions.issue_in_transaction(account_id)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

        return AuthenticatedAccountSession(account_id=account_id, token=token)
