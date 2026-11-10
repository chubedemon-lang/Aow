"""Persistent per-username throttling for the synthetic SQLite auth service.

This is a local domain primitive, not a network edge limiter. A future adapter
must also rate-limit by trusted source identity and enforce transport security.
Only keyed HMAC digests are stored; the HMAC secret is supplied by the operator
and must remain stable across restarts if existing buckets should remain active.
"""
import hashlib
import hmac
import math
import sqlite3
import time


_MAX_WINDOW_SECONDS = 86_400
_MAX_LOCKOUT_SECONDS = 86_400
_MAX_ATTEMPTS = 10_000
_MAX_BUCKETS = 1_000_000
_MAX_PRINCIPAL_BYTES = 256
_INVALID_PRINCIPAL = b"\x00invalid-principal"


class AuthenticationRateLimited(ValueError):
    """The principal has exhausted its configured authentication attempts."""


class SqliteAuthRateLimiter:
    """A durable fixed-window failure counter keyed by a private HMAC digest.

    The limiter shares the account-auth SQLite connection. Public methods own
    their transactions; the *_in_transaction methods deliberately leave commit
    and rollback to the caller. It limits a username bucket only, not source IPs.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        secret: bytes,
        *,
        max_attempts: int = 8,
        window_seconds: int = 60,
        lockout_seconds: int = 60,
        max_buckets: int = 10_000,
        clock=None,
    ):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        if type(secret) is not bytes or len(secret) < 32:
            raise ValueError("rate-limit HMAC secret must contain at least 32 bytes")
        if type(max_attempts) is not int or not 1 <= max_attempts <= _MAX_ATTEMPTS:
            raise ValueError("invalid maximum authentication attempts")
        if type(window_seconds) is not int or not 1 <= window_seconds <= _MAX_WINDOW_SECONDS:
            raise ValueError("invalid authentication rate-limit window")
        if type(lockout_seconds) is not int or not 1 <= lockout_seconds <= _MAX_LOCKOUT_SECONDS:
            raise ValueError("invalid authentication lockout duration")
        if type(max_buckets) is not int or not 1 <= max_buckets <= _MAX_BUCKETS:
            raise ValueError("invalid authentication rate-limit bucket capacity")

        self.db = connection
        self._secret = secret
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.max_buckets = max_buckets
        self.clock = clock if clock is not None else time.time
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS auth_attempt_limits (
                principal_digest BLOB PRIMARY KEY
                    CHECK(typeof(principal_digest) = 'blob' AND length(principal_digest) = 32),
                window_started_at REAL NOT NULL CHECK(window_started_at >= 0),
                attempt_count INTEGER NOT NULL CHECK(attempt_count >= 0),
                blocked_until REAL
                    CHECK(blocked_until IS NULL OR blocked_until >= 0)
            )"""
        )
        self.db.commit()

    def _now(self) -> float:
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

    def _principal_digest(self, principal) -> bytes:
        """Return a bounded, keyed identifier; never persist the supplied name."""
        if isinstance(principal, str):
            try:
                raw = principal.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raw = _INVALID_PRINCIPAL
            if (
                not raw
                or len(raw) > _MAX_PRINCIPAL_BYTES
                or principal != principal.strip()
                or "\x00" in principal
            ):
                raw = _INVALID_PRINCIPAL
            else:
                raw = b"\x01username\x00" + raw
        else:
            raw = _INVALID_PRINCIPAL
        return hmac.new(self._secret, raw, hashlib.sha256).digest()

    def _require_transaction(self) -> None:
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")

    def _load_state(self, digest: bytes):
        row = self.db.execute(
            """SELECT window_started_at, attempt_count, blocked_until
               FROM auth_attempt_limits WHERE principal_digest = ?""",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        started, attempts, blocked_until = row
        if (
            isinstance(started, bool)
            or not isinstance(started, (int, float))
            or not math.isfinite(float(started))
            or started < 0
            or type(attempts) is not int
            or attempts < 0
            or (
                blocked_until is not None
                and (
                    isinstance(blocked_until, bool)
                    or not isinstance(blocked_until, (int, float))
                    or not math.isfinite(float(blocked_until))
                    or blocked_until < 0
                )
            )
        ):
            raise RuntimeError("authentication rate-limit state is corrupt")
        return float(started), attempts, (
            None if blocked_until is None else float(blocked_until)
        )

    def _transaction(self, operation):
        if self.db.in_transaction:
            raise ValueError("connection already has an active transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            result = operation()
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise

    def check_allowed(self, principal) -> None:
        """Reject an active lockout; expired buckets are removed atomically."""
        digest = self._principal_digest(principal)
        now = self._now()

        def operation():
            state = self._load_state(digest)
            if state is None:
                return
            started, attempts, blocked_until = state
            if blocked_until is not None:
                if now < blocked_until:
                    raise AuthenticationRateLimited("authentication temporarily unavailable")
                self.db.execute(
                    "DELETE FROM auth_attempt_limits WHERE principal_digest = ?",
                    (digest,),
                )
                return
            if now >= started + self.window_seconds:
                self.db.execute(
                    "DELETE FROM auth_attempt_limits WHERE principal_digest = ?",
                    (digest,),
                )
                return
            # A threshold row without a lockout is inconsistent; fail closed.
            if attempts >= self.max_attempts:
                raise AuthenticationRateLimited("authentication temporarily unavailable")

        self._transaction(operation)

    def record_failure_in_transaction(self, principal) -> int:
        """Record one failed attempt without committing the caller's transaction."""
        self._require_transaction()
        digest = self._principal_digest(principal)
        now = self._now()
        # Bound database growth from arbitrary unknown usernames. Expired
        # failure windows and completed lockouts no longer need a stored bucket.
        self.db.execute(
            """DELETE FROM auth_attempt_limits
               WHERE (blocked_until IS NULL AND window_started_at <= ?)
                  OR (blocked_until IS NOT NULL AND blocked_until <= ?)""",
            (now - self.window_seconds, now),
        )
        state = self._load_state(digest)

        if state is None:
            bucket_count = self.db.execute(
                "SELECT count(*) FROM auth_attempt_limits"
            ).fetchone()[0]
            if bucket_count >= self.max_buckets:
                raise AuthenticationRateLimited("authentication temporarily unavailable")
            started, attempts, blocked_until = now, 0, None
        else:
            started, attempts, blocked_until = state
            if blocked_until is not None and now < blocked_until:
                return attempts
            if blocked_until is not None or now >= started + self.window_seconds:
                started, attempts, blocked_until = now, 0, None

        attempts += 1
        if attempts >= self.max_attempts:
            blocked_until = now + self.lockout_seconds
        self.db.execute(
            """INSERT INTO auth_attempt_limits
               (principal_digest, window_started_at, attempt_count, blocked_until)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(principal_digest) DO UPDATE SET
                   window_started_at = excluded.window_started_at,
                   attempt_count = excluded.attempt_count,
                   blocked_until = excluded.blocked_until""",
            (digest, started, attempts, blocked_until),
        )
        return attempts

    def record_failure(self, principal) -> int:
        """Record one failed attempt in a transaction owned by this method."""
        return self._transaction(
            lambda: self.record_failure_in_transaction(principal)
        )

    def record_success_in_transaction(self, principal) -> None:
        """Clear the principal's failure bucket without committing the caller."""
        self._require_transaction()
        digest = self._principal_digest(principal)
        self.db.execute(
            "DELETE FROM auth_attempt_limits WHERE principal_digest = ?",
            (digest,),
        )

    def record_success(self, principal) -> None:
        """Clear the principal's failure bucket in an owned transaction."""
        self._transaction(
            lambda: self.record_success_in_transaction(principal)
        )
