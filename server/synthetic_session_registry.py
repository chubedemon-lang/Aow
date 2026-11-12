"""Bounded local-only session registry; not an AOW protocol implementation.

One active session per account and character. Caller-provided connection IDs are
opaque local identifiers, never wire-level identifiers. Registry-managed
operations are serialized with a re-entrant lock so capacity and uniqueness
checks remain atomic under concurrent callers.
"""
import threading

from .synthetic_session_state import Phase, Session, SessionError


class RegistryError(ValueError):
    pass


class SessionRegistry:
    def __init__(self, capacity=1024):
        if type(capacity) is not int or not 1 <= capacity <= 100000:
            raise RegistryError("invalid capacity")
        self.capacity = capacity
        self._sessions = {}
        self._lock = threading.RLock()

    @staticmethod
    def _key(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.strip():
            raise RegistryError("invalid connection identifier")
        return value

    def open(self, connection_id):
        key = self._key(connection_id)
        with self._lock:
            if key in self._sessions:
                raise RegistryError("connection already registered")
            if len(self._sessions) >= self.capacity:
                raise RegistryError("capacity exceeded")
            session = Session()
            self._sessions[key] = session
            return session

    def get(self, connection_id):
        """Return the registered session for read-only inspection.

        Callers must use registry methods for state transitions rather than
        mutating the returned Session directly; doing so would bypass registry
        uniqueness checks. The returned Session object is not independently
        thread-safe.
        """
        key = self._key(connection_id)
        with self._lock:
            try:
                return self._sessions[key]
            except KeyError:
                raise RegistryError("unknown connection") from None

    def authenticate(self, connection_id, account_id):
        with self._lock:
            session = self._get_locked(connection_id)
            # Validate the transition before changing any shared registry state.
            if session.snapshot.phase is not Phase.NEW:
                raise SessionError("authentication not allowed")
            account_id = Session._identifier(account_id)
            if any(other is not session and other.snapshot.account_id == account_id
                   for other in self._sessions.values()):
                raise RegistryError("account already active")
            session.authenticate(account_id)

    def select_character(self, connection_id, character_id):
        with self._lock:
            session = self._get_locked(connection_id)
            if session.snapshot.phase is not Phase.AUTHENTICATED:
                raise SessionError("character selection not allowed")
            character_id = Session._identifier(character_id)
            if any(other is not session and other.snapshot.character_id == character_id
                   for other in self._sessions.values()):
                raise RegistryError("character already active")
            session.select_character(character_id)

    def _get_locked(self, connection_id):
        key = self._key(connection_id)
        try:
            return self._sessions[key]
        except KeyError:
            raise RegistryError("unknown connection") from None

    def transfer_connection(self, old_connection_id, new_connection_id, *, verified=False):
        """Atomically rebind a local connection after external verification.

        This does not authenticate the new connection or represent an AOW
        reconnect packet. Caller must independently verify the handoff.
        """
        if verified is not True:
            raise RegistryError("external verification required")
        old_key = self._key(old_connection_id)
        new_key = self._key(new_connection_id)
        with self._lock:
            if old_key not in self._sessions:
                raise RegistryError("unknown source connection")
            if new_key in self._sessions:
                raise RegistryError("target connection already registered")
            session = self._sessions.pop(old_key)
            self._sessions[new_key] = session
            return session

    def close(self, connection_id):
        key = self._key(connection_id)
        with self._lock:
            session = self._sessions.pop(key, None)
            if session is None:
                return False
            session.close()
            return True

    def close_all(self):
        with self._lock:
            for key in tuple(self._sessions):
                self._close_locked(key)

    def _close_locked(self, key):
        session = self._sessions.pop(key, None)
        if session is not None:
            session.close()

    @property
    def active_count(self):
        with self._lock:
            return len(self._sessions)
