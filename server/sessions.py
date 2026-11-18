"""Local-only synthetic session manager; NOT the AOW APK authentication protocol.

Session tokens are server-issued, opaque, short-lived and never persisted.
"""
from contextlib import closing
import math
import secrets
import threading
import time


class SessionError(Exception):
    """Invalid, expired, or unauthorized synthetic session."""


class SessionManager:
    def __init__(self, ttl_seconds=900, clock=None):
        if type(ttl_seconds) is not int or ttl_seconds < 1:
            raise ValueError("invalid ttl")
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self.ttl_seconds = ttl_seconds
        self.clock = clock if clock is not None else time.monotonic
        self._sessions = {}
        self._last_clock_value = None
        self._lock = threading.RLock()

    def _now(self):
        """Read a finite, non-negative, nondecreasing built-in clock value.

        All callers hold _lock. Rejecting rollback prevents a faulty injected
        clock from extending sessions or making expired sessions appear valid.
        """
        try:
            now = self.clock()
        except Exception as exc:
            raise SessionError("session clock failed") from exc

        if type(now) is int:
            valid = now >= 0
        elif type(now) is float:
            valid = math.isfinite(now) and now >= 0
        else:
            valid = False
        if not valid:
            raise SessionError(
                "session clock must return a finite non-negative built-in number"
            )
        if (
            self._last_clock_value is not None
            and now < self._last_clock_value
        ):
            raise SessionError("session clock moved backwards")
        self._last_clock_value = now
        return now

    def issue(self, account_id):
        """Operator/test-only issuance after independently verified authentication."""
        if type(account_id) is not int or account_id < 1:
            raise ValueError("invalid account id")
        with self._lock:
            now = self._now()
            try:
                expires = now + self.ttl_seconds
            except OverflowError as exc:
                raise SessionError("session expiry is not representable") from exc
            if type(expires) is float and not math.isfinite(expires):
                raise SessionError("session expiry is not finite")
            token = secrets.token_urlsafe(32)
            self._sessions[token] = (account_id, expires)
            return token

    def resolve(self, token):
        if type(token) is not str or not token:
            raise SessionError("invalid session")
        with self._lock:
            record = self._sessions.get(token)
            if record is None:
                raise SessionError("invalid session")
            account_id, expires = record
            if self._now() >= expires:
                del self._sessions[token]
                raise SessionError("expired session")
            return account_id

    def require_character(self, token, character_id, domain):
        """Authorize a character against the account linked to this session.

        The domain owns the connection factory. Close the short-lived connection
        explicitly: sqlite3.Connection's context manager manages transactions but
        does not close the underlying database connection.
        """
        if type(character_id) is not int or character_id < 1:
            raise SessionError("invalid character")
        # Keep revocation/purge serialized with the complete authorization
        # check. Resolving under the lock and then releasing it before the
        # ownership query would let revoke() finish while this method was still
        # returning an authorization result for that token.
        with self._lock:
            account_id = self.resolve(token)
            with closing(domain.connect()) as db:
                owned = db.execute(
                    "SELECT 1 FROM characters WHERE id=? AND account_id=?",
                    (character_id, account_id),
                ).fetchone()
            if owned is None:
                raise SessionError("character not owned by session")
            return character_id

    def revoke(self, token):
        # Do not invoke attacker-controlled __hash__/__eq__ hooks on str subclasses.
        if type(token) is not str or not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def purge_expired(self):
        with self._lock:
            now = self._now()
            expired = [token for token, (_, expiry) in self._sessions.items() if now >= expiry]
            for token in expired:
                del self._sessions[token]
            return len(expired)
