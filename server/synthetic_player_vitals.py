"""Session-scoped synthetic player vitals, not an AOW gameplay contract."""
from dataclasses import dataclass

from server.synthetic_session_lifecycle import SessionState


class PlayerVitalsError(ValueError):
    """Invalid operation or stale session binding."""


@dataclass(frozen=True)
class Vitals:
    hp: int
    max_hp: int


class SessionVitals:
    """Immutable snapshots; bind to one character-ready session epoch."""

    def __init__(self):
        self._session = None
        self._snapshot = None
        self._vitals = None

    @property
    def vitals(self):
        return self._vitals

    def sync(self, session):
        snapshot = session.snapshot
        if (session is not self._session or snapshot is not self._snapshot
                or snapshot.state not in (SessionState.CHARACTER_READY, SessionState.IN_MAP)):
            self._session = None
            self._snapshot = None
            self._vitals = None
        return self._vitals

    def initialize(self, session, max_hp):
        self.sync(session)
        snapshot = session.snapshot
        if snapshot.state is not SessionState.CHARACTER_READY:
            raise PlayerVitalsError("character not ready")
        if self._vitals is not None:
            raise PlayerVitalsError("vitals already initialized")
        if type(max_hp) is not int or not 1 <= max_hp <= 1_000_000:
            raise PlayerVitalsError("invalid max hp")
        self._session = session
        self._snapshot = snapshot
        self._vitals = Vitals(max_hp, max_hp)
        return self._vitals

    def damage(self, session, amount):
        self._require_active(session)
        self._amount(amount)
        current = self._vitals
        self._vitals = Vitals(max(0, current.hp - amount), current.max_hp)
        return self._vitals

    def heal(self, session, amount):
        self._require_active(session)
        self._amount(amount)
        current = self._vitals
        self._vitals = Vitals(min(current.max_hp, current.hp + amount), current.max_hp)
        return self._vitals

    @staticmethod
    def _amount(amount):
        if type(amount) is not int or not 0 <= amount <= 1_000_000:
            raise PlayerVitalsError("invalid amount")

    def _require_active(self, session):
        self.sync(session)
        if self._vitals is None:
            raise PlayerVitalsError("vitals not initialized for current session")
