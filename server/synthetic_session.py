"""Transport-independent synthetic session state machine.

No AOW packet, handshake or login semantics are asserted here.
This module is solely for testing server-side lifecycle invariants.
"""
from __future__ import annotations

from enum import Enum, auto


class SessionError(ValueError):
    """A session transition violates the local lifecycle contract."""


class Phase(Enum):
    CONNECTED = auto()
    AUTHENTICATED = auto()
    PLAYER_SELECTED = auto()
    IN_MAP = auto()
    CLOSED = auto()


class SyntheticSession:
    """One connection; no cross-connection or persistent account state.

    Lifecycle fields are exposed as read-only properties. Callers must use
    the transition methods so an accidental direct assignment cannot skip a
    phase or preserve identity after closure.
    """

    __slots__ = ("_phase", "_account_id", "_player_id", "_map_id")

    def __init__(self) -> None:
        self._phase = Phase.CONNECTED
        self._account_id: str | None = None
        self._player_id: str | None = None
        self._map_id: int | None = None

    @property
    def phase(self) -> Phase:
        return self._phase

    @property
    def account_id(self) -> str | None:
        return self._account_id

    @property
    def player_id(self) -> str | None:
        return self._player_id

    @property
    def map_id(self) -> int | None:
        return self._map_id

    def _require(self, expected: Phase) -> None:
        if self._phase is not expected:
            raise SessionError(f"expected {expected.name}, got {self._phase.name}")

    @staticmethod
    def _validate_identifier(value: str, label: str) -> None:
        """Bound synthetic identifiers and reject control characters."""
        if (type(value) is not str or not value.strip() or len(value) > 128
                or not value.isprintable()):
            raise SessionError(f"{label} must be a nonempty printable string (max 128)")

    def authenticate(self, account_id: str) -> None:
        self._require(Phase.CONNECTED)
        self._validate_identifier(account_id, "account_id")
        self._account_id = account_id
        self._phase = Phase.AUTHENTICATED

    def select_player(self, player_id: str) -> None:
        self._require(Phase.AUTHENTICATED)
        self._validate_identifier(player_id, "player_id")
        self._player_id = player_id
        self._phase = Phase.PLAYER_SELECTED

    def enter_map(self, map_id: int) -> None:
        self._require(Phase.PLAYER_SELECTED)
        if type(map_id) is not int or map_id < 0:
            raise SessionError("map_id must be a nonnegative integer")
        self._map_id = map_id
        self._phase = Phase.IN_MAP

    def leave_map(self) -> None:
        self._require(Phase.IN_MAP)
        self._map_id = None
        self._phase = Phase.PLAYER_SELECTED

    def close(self) -> None:
        """Idempotently revoke all local session state."""
        self._account_id = None
        self._player_id = None
        self._map_id = None
        self._phase = Phase.CLOSED
