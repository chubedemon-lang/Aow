"""Transport-agnostic synthetic session lifecycle; NOT an AOW wire contract.

No network operations, credentials, packet formats, or official endpoints.
"""
from dataclasses import dataclass
from enum import Enum


class SessionState(str, Enum):
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    CHARACTER_READY = "character_ready"
    IN_MAP = "in_map"
    CLOSED = "closed"


class SessionTransitionError(ValueError):
    """Invalid lifecycle transition; no state is changed."""


@dataclass(frozen=True)
class SessionSnapshot:
    state: SessionState
    player_id: str | None = None
    map_id: str | None = None


class SyntheticSession:
    """Fail-closed lifecycle with detached snapshots and monotonic revision."""

    def __init__(self):
        self._snapshot = SessionSnapshot(SessionState.CONNECTED)
        self._revision = 0

    @property
    def snapshot(self):
        # Return a detached value; frozen dataclasses can be bypassed with
        # object.__setattr__, so never expose the authoritative instance.
        current = self._snapshot
        return SessionSnapshot(current.state, current.player_id, current.map_id)

    @property
    def revision(self):
        """Monotonic synthetic lifecycle epoch for bound local resources."""
        return self._revision

    def _require(self, expected):
        if self._snapshot.state is not expected:
            raise SessionTransitionError("invalid session transition")

    @staticmethod
    def _identifier(value):
        if type(value) is not str or not 1 <= len(value) <= 128:
            raise SessionTransitionError("invalid identifier")
        if not all(c.isascii() and (c.isalnum() or c in "_-") for c in value):
            raise SessionTransitionError("invalid identifier")
        return value

    def authenticate(self):
        self._require(SessionState.CONNECTED)
        self._snapshot = SessionSnapshot(SessionState.AUTHENTICATED)
        self._revision += 1
        return self.snapshot

    def select_character(self, player_id):
        self._require(SessionState.AUTHENTICATED)
        player_id = self._identifier(player_id)
        self._snapshot = SessionSnapshot(SessionState.CHARACTER_READY, player_id)
        self._revision += 1
        return self.snapshot

    def join_map(self, map_id):
        self._require(SessionState.CHARACTER_READY)
        map_id = self._identifier(map_id)
        self._snapshot = SessionSnapshot(SessionState.IN_MAP, self._snapshot.player_id, map_id)
        self._revision += 1
        return self.snapshot

    def leave_map(self):
        self._require(SessionState.IN_MAP)
        self._snapshot = SessionSnapshot(SessionState.CHARACTER_READY, self._snapshot.player_id)
        self._revision += 1
        return self.snapshot

    def close(self):
        if self._snapshot.state is not SessionState.CLOSED:
            self._snapshot = SessionSnapshot(SessionState.CLOSED)
            self._revision += 1
        return self.snapshot
