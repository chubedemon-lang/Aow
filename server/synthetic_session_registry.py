"""Bounded local-only session registry; not an AOW protocol implementation.

One active session per account and character. Caller-provided connection IDs are
opaque local identifiers, never wire-level identifiers.
"""
from .synthetic_session_state import Phase, Session, SessionError


class RegistryError(ValueError):
    pass


class SessionRegistry:
    def __init__(self, capacity=1024):
        if type(capacity) is not int or not 1 <= capacity <= 100000:
            raise RegistryError("invalid capacity")
        self.capacity = capacity
        self._sessions = {}

    @staticmethod
    def _key(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.strip():
            raise RegistryError("invalid connection identifier")
        return value

    def open(self, connection_id):
        key = self._key(connection_id)
        if key in self._sessions:
            raise RegistryError("connection already registered")
        if len(self._sessions) >= self.capacity:
            raise RegistryError("capacity exceeded")
        session = Session()
        self._sessions[key] = session
        return session

    def get(self, connection_id):
        key = self._key(connection_id)
        try:
            return self._sessions[key]
        except KeyError:
            raise RegistryError("unknown connection") from None

    def authenticate(self, connection_id, account_id):
        session = self.get(connection_id)
        # Validate the transition before changing any shared registry state.
        if session.snapshot.phase is not Phase.NEW:
            raise SessionError("authentication not allowed")
        account_id = Session._identifier(account_id)
        if any(other is not session and other.snapshot.account_id == account_id
               for other in self._sessions.values()):
            raise RegistryError("account already active")
        session.authenticate(account_id)

    def select_character(self, connection_id, character_id):
        session = self.get(connection_id)
        if session.snapshot.phase is not Phase.AUTHENTICATED:
            raise SessionError("character selection not allowed")
        character_id = Session._identifier(character_id)
        if any(other is not session and other.snapshot.character_id == character_id
               for other in self._sessions.values()):
            raise RegistryError("character already active")
        session.select_character(character_id)


    def transfer_connection(self, old_connection_id, new_connection_id, *, verified=False):
        """Atomically rebind a local connection after external verification.

        This does not authenticate the new connection or represent an AOW
        reconnect packet. Caller must independently verify the handoff.
        """
        if verified is not True:
            raise RegistryError("external verification required")
        old_key = self._key(old_connection_id)
        new_key = self._key(new_connection_id)
        if old_key not in self._sessions:
            raise RegistryError("unknown source connection")
        if new_key in self._sessions:
            raise RegistryError("target connection already registered")
        session = self._sessions.pop(old_key)
        self._sessions[new_key] = session
        return session

    def close(self, connection_id):
        key = self._key(connection_id)
        session = self._sessions.pop(key, None)
        if session is None:
            return False
        session.close()
        return True

    def close_all(self):
        for key in tuple(self._sessions):
            self.close(key)

    @property
    def active_count(self):
        return len(self._sessions)
