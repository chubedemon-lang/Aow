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
        if type(connection) is not sqlite3.Connection:
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
        existing = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name='auth_attempt_limits'"
        ).fetchone()
        if existing == ("table",):
            # Keep the common initialized path read-only. Schema validation
            # uses a private in-memory probe and does not take the main DB's
            # writer reservation.
            self._validate_schema()
            return
        if existing is not None:
            raise ValueError("incompatible authentication rate-limit table")

        # Create a missing schema atomically and re-check after obtaining the
        # write reservation in case another process initialized it meanwhile.
        self.db.execute("BEGIN IMMEDIATE")
        try:
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
            self._validate_schema()
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def _validate_schema(self) -> None:
        """Fail closed on incompatible columns, indexes, triggers, or CHECKs."""
        table = self.db.execute(
            "SELECT type, sql FROM sqlite_master WHERE name='auth_attempt_limits'"
        ).fetchone()
        if table is None or table[0] != "table" or type(table[1]) is not str:
            raise ValueError("incompatible authentication rate-limit table")

        expected_columns = [
            ("principal_digest", "BLOB", 0, None, 1, 0),
            ("window_started_at", "REAL", 1, None, 0, 0),
            ("attempt_count", "INTEGER", 1, None, 0, 0),
            ("blocked_until", "REAL", 0, None, 0, 0),
        ]
        rows = self.db.execute(
            "PRAGMA table_xinfo(auth_attempt_limits)"
        ).fetchall()
        actual_columns = [
            (
                row[1],
                str(row[2]).strip().upper(),
                int(row[3]),
                row[4],
                int(row[5]),
                int(row[6]),
            )
            for row in rows
        ]
        if actual_columns != expected_columns:
            raise ValueError("incompatible authentication rate-limit schema")

        indexes = self.db.execute(
            "PRAGMA index_list(auth_attempt_limits)"
        ).fetchall()
        if (
            len(indexes) != 1
            or int(indexes[0][2]) != 1
            or indexes[0][3] != "pk"
            or int(indexes[0][4]) != 0
        ):
            raise ValueError("incompatible authentication rate-limit primary key")
        if indexes[0][1] != "sqlite_autoindex_auth_attempt_limits_1":
            raise ValueError("incompatible authentication rate-limit primary key")
        indexed_columns = tuple(
            row[2]
            for row in self.db.execute(
                "PRAGMA index_info(sqlite_autoindex_auth_attempt_limits_1)"
            ).fetchall()
        )
        if indexed_columns != ("principal_digest",):
            raise ValueError("incompatible authentication rate-limit primary key")

        trigger = self.db.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='trigger' AND tbl_name='auth_attempt_limits' LIMIT 1"
        ).fetchone()
        if trigger is not None:
            raise ValueError("incompatible authentication rate-limit triggers")

        self._validate_schema_constraints(table[1])

    @staticmethod
    def _validate_schema_constraints(create_sql: str) -> None:
        """Exercise required CHECK/NOT NULL/PRIMARY KEY rules on a private clone."""
        probe = sqlite3.connect(":memory:")
        try:
            probe.execute(create_sql)
            insert_sql = (
                "INSERT INTO auth_attempt_limits "
                "(principal_digest, window_started_at, attempt_count, blocked_until) "
                "VALUES (?, ?, ?, ?)"
            )
            valid_digest = bytes(range(32))
            probe.execute(insert_sql, (valid_digest, 0.0, 0, None))

            invalid_rows = (
                (None, 0.0, 0, None),
                (b"x", 0.0, 0, None),
                ("x" * 32, 0.0, 0, None),
                (bytes([1]) * 32, -1.0, 0, None),
                (bytes([2]) * 32, 0.0, -1, None),
                (bytes([3]) * 32, 0.0, 0, -1.0),
                (bytes([4]) * 32, None, 0, None),
                (bytes([5]) * 32, 0.0, None, None),
            )
            for row in invalid_rows:
                try:
                    probe.execute(insert_sql, row)
                except sqlite3.IntegrityError:
                    continue
                raise ValueError(
                    "incompatible authentication rate-limit CHECK constraints"
                )

            try:
                probe.execute(insert_sql, (valid_digest, 1.0, 0, None))
            except sqlite3.IntegrityError:
                pass
            else:
                raise ValueError(
                    "incompatible authentication rate-limit primary key"
                )
        except ValueError:
            raise
        except sqlite3.DatabaseError:
            raise ValueError(
                "incompatible authentication rate-limit schema"
            ) from None
        finally:
            probe.close()

    def _now(self) -> float:
        try:
            value = self.clock()
        except Exception:
            # Clock exception text may contain operator-private implementation
            # details; expose only a stable, generic failure at this boundary.
            raise ValueError("authentication rate-limit clock failed") from None
        # Clock providers are injected by the operator, but still form a
        # validation boundary. Numeric subclasses can override __float__ and
        # execute arbitrary code during expiry checks; accept built-ins only,
        # matching the durable-session and process-local session validators.
        if type(value) not in (int, float):
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
        # Do not dispatch encode()/strip()/len() on caller-defined str subclasses.
        # Non-exact strings share the bounded invalid-principal bucket.
        if type(principal) is str:
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

    def _load_state(self, digest: bytes, now: float):
        row = self.db.execute(
            """SELECT window_started_at, attempt_count, blocked_until
               FROM auth_attempt_limits WHERE principal_digest = ?""",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        started, attempts, blocked_until = row
        if (
            type(started) not in (int, float)
            or not math.isfinite(float(started))
            or started < 0
            or started > now
            or type(attempts) is not int
            or attempts < 0
            or (
                blocked_until is not None
                and (
                    type(blocked_until) not in (int, float)
                    or not math.isfinite(float(blocked_until))
                    or blocked_until < 0
                    or blocked_until < started
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

        def operation():
            # Sample time only after BEGIN IMMEDIATE has acquired the writer
            # reservation. A caller waiting on SQLite must not evaluate an
            # expired lockout using a stale pre-lock timestamp.
            now = self._now()
            state = self._load_state(digest, now)
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
        # A caller-owned transaction may be DEFERRED. Force SQLite to acquire
        # its writer reservation before sampling time; otherwise a later write
        # could wait behind another writer while this failure window uses a
        # stale timestamp captured before the wait. The zero-row UPDATE changes
        # no data but upgrades the transaction to a reserved writer when safe.
        self.db.execute(
            "UPDATE auth_attempt_limits SET attempt_count = attempt_count WHERE 0"
        )
        now = self._now()
        # Bound database growth from arbitrary unknown usernames. Expired
        # failure windows and completed lockouts no longer need a stored bucket.
        self.db.execute(
            """DELETE FROM auth_attempt_limits
               WHERE (blocked_until IS NULL AND window_started_at <= ?)
                  OR (blocked_until IS NOT NULL AND blocked_until <= ?)""",
            (now - self.window_seconds, now),
        )
        state = self._load_state(digest, now)

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
