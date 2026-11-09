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
    """One connection; no cross-connection or persistent account state."""

    def __init__(self) -> None:
        self.phase = Phase.CONNECTED
        self.account_id: str | None = None
        self.player_id: str | None = None
        self.map_id: int | None = None

    def _require(self, expected: Phase) -> None:
        if self.phase is not expected:
            raise SessionError(f"expected {expected.name}, got {self.phase.name}")

    @staticmethod
    def _validate_identifier(value: str, label: str) -> None:
        """Bound synthetic identifiers and reject control characters."""
        if (type(value) is not str or not value.strip() or len(value) > 128
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
            raise SessionError(f"{label} must be a nonempty printable string (max 128)")

    def authenticate(self, account_id: str) -> None:
        self._require(Phase.CONNECTED)
        self._validate_identifier(account_id, "account_id")
        self.account_id = account_id
        self.phase = Phase.AUTHENTICATED

    def select_player(self, player_id: str) -> None:
        self._require(Phase.AUTHENTICATED)
        self._validate_identifier(player_id, "player_id")
        self.player_id = player_id
        self.phase = Phase.PLAYER_SELECTED

    def enter_map(self, map_id: int) -> None:
        self._require(Phase.PLAYER_SELECTED)
        if type(map_id) is not int or map_id < 0:
            raise SessionError("map_id must be a nonnegative integer")
        self.map_id = map_id
        self.phase = Phase.IN_MAP

    def leave_map(self) -> None:
        self._require(Phase.IN_MAP)
        self.map_id = None
        self.phase = Phase.PLAYER_SELECTED

    def close(self) -> None:
        """Idempotently revoke all local session state."""
        self.account_id = None
        self.player_id = None
        self.map_id = None
        self.phase = Phase.CLOSED
