"""Local-only synthetic session manager; NOT the AOW APK authentication protocol.

Session tokens are server-issued, opaque, short-lived and never persisted.
"""
import secrets
import threading
import time


class SessionError(Exception):
    """Invalid, expired, or unauthorized synthetic session."""


class SessionManager:
    def __init__(self, ttl_seconds=900, clock=None):
        if type(ttl_seconds) is not int or ttl_seconds < 1:
            raise ValueError("invalid ttl")
        self.ttl_seconds = ttl_seconds
        self.clock = clock if clock is not None else time.monotonic
        self._sessions = {}
        self._lock = threading.RLock()

    def issue(self, account_id):
        """Operator/test-only issuance after independently verified authentication."""
        if type(account_id) is not int or account_id < 1:
            raise ValueError("invalid account id")
        with self._lock:
            token = secrets.token_urlsafe(32)
            self._sessions[token] = (account_id, self.clock() + self.ttl_seconds)
            return token

    def resolve(self, token):
        if not isinstance(token, str) or not token:
            raise SessionError("invalid session")
        with self._lock:
            record = self._sessions.get(token)
            if record is None:
                raise SessionError("invalid session")
            account_id, expires = record
            if self.clock() >= expires:
                del self._sessions[token]
                raise SessionError("expired session")
            return account_id

    def require_character(self, token, character_id, domain):
        """Authorize a character against the account linked to this session."""
        if type(character_id) is not int or character_id < 1:
            raise SessionError("invalid character")
        account_id = self.resolve(token)
        with domain.connect() as db:
            owned = db.execute(
                "SELECT 1 FROM characters WHERE id=? AND account_id=?",
                (character_id, account_id),
            ).fetchone()
        if owned is None:
            raise SessionError("character not owned by session")
        return character_id

    def revoke(self, token):
        with self._lock:
            self._sessions.pop(token, None)

    def purge_expired(self):
        with self._lock:
            now = self.clock()
            expired = [token for token, (_, expiry) in self._sessions.items() if now >= expiry]
            for token in expired:
                del self._sessions[token]
            return len(expired)
