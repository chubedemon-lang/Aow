"""Synthetic in-memory world positions; no AOW packet assumptions.

Callers must provide server-monotonic timestamps, never client timestamps.
Single-process only. Mutations are not thread-safe.
"""
from dataclasses import dataclass
import math

from server.movement_validation import MovementValidator, Position, MovementError
from server.player_presence import PresenceRegistry, PresenceError
from server.session_state import Session, SessionState


@dataclass(frozen=True)
class WorldPosition:
    player_id: str
    session_id: str
    map_id: str
    position: Position
    timestamp: float


class WorldPositionTracker:
    def __init__(self, presence: PresenceRegistry, max_speed: float):
        self.presence = presence
        self.validator = MovementValidator(max_speed)
        self._positions: dict[str, WorldPosition] = {}

    def _owner_map(self, session: Session) -> str:
        if not isinstance(session, Session):
            raise TypeError("session required")
        current = self.presence.get(session.player_id)
        if (session.state != SessionState.IN_WORLD or current is None
                or current.session_id != session.session_id or current.map_id is None):
            raise PresenceError("active world/map ownership required")
        return current.map_id

    @staticmethod
    def _time(timestamp: float) -> float:
        if (not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool)
                or not math.isfinite(timestamp) or timestamp < 0):
            raise MovementError("invalid server timestamp")
        return float(timestamp)

    def spawn(self, session: Session, position: Position, timestamp: float) -> WorldPosition:
        map_id = self._owner_map(session)
        if not isinstance(position, Position):
            raise TypeError("position required")
        now = self._time(timestamp)
        if session.player_id in self._positions:
            raise PresenceError("position already initialized; despawn first")
        state = WorldPosition(session.player_id, session.session_id, map_id, position, now)
        self._positions[session.player_id] = state
        return state

    def move(self, session: Session, position: Position, timestamp: float) -> WorldPosition:
        map_id = self._owner_map(session)
        now = self._time(timestamp)
        current = self._positions.get(session.player_id)
        if (current is None or current.session_id != session.session_id
                or current.map_id != map_id):
            raise PresenceError("position not initialized for current map")
        self.validator.validate(current.position, position, now - current.timestamp)
        updated = WorldPosition(current.player_id, current.session_id, map_id, position, now)
        self._positions[session.player_id] = updated
        return updated

    def despawn(self, session: Session) -> None:
        if not isinstance(session, Session):
            raise TypeError("session required")
        current = self._positions.get(session.player_id)
        if current is None or current.session_id != session.session_id:
            raise PresenceError("position not owned by session")
        del self._positions[session.player_id]

    def get(self, player_id: str) -> WorldPosition | None:
        return self._positions.get(player_id)
