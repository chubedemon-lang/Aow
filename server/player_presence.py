"""Transport-independent player presence registry.

Single-process, synchronous domain model. Not an AOW APK protocol implementation.
"""
from dataclasses import dataclass
from server.session_state import Session, SessionState, SessionTransitionError


class PresenceError(ValueError):
    """Player/session ownership or presence invariant violated."""


@dataclass(frozen=True)
class PlayerPresence:
    player_id: str
    session_id: str
    map_id: str | None = None


class PresenceRegistry:
    def __init__(self):
        self._players: dict[str, PlayerPresence] = {}
        self._sessions: dict[str, str] = {}

    def bind(self, session: Session) -> PlayerPresence:
        if session.state != SessionState.AUTHENTICATED or session.player_id is None:
            raise SessionTransitionError("authenticated session required")
        if session.player_id in self._players:
            raise PresenceError("player already connected")
        if session.session_id in self._sessions:
            raise PresenceError("session already bound")
        presence = PlayerPresence(session.player_id, session.session_id)
        self._players[session.player_id] = presence
        self._sessions[session.session_id] = session.player_id
        return presence

    def enter_map(self, session: Session, map_id: str) -> PlayerPresence:
        current = self._require_owner(session)
        if session.state != SessionState.IN_WORLD:
            raise SessionTransitionError("world entry required")
        if not isinstance(map_id, str) or not (1 <= len(map_id) <= 128):
            raise ValueError("invalid map_id")
        if current.map_id is not None:
            raise PresenceError("leave current map before entering another")
        updated = PlayerPresence(current.player_id, current.session_id, map_id)
        self._players[current.player_id] = updated
        return updated

    def leave_map(self, session: Session) -> PlayerPresence:
        current = self._require_owner(session)
        if current.map_id is None:
            raise PresenceError("player not on map")
        updated = PlayerPresence(current.player_id, current.session_id)
        self._players[current.player_id] = updated
        return updated

    def release(self, session: Session) -> None:
        # Called before/after session.close(); ownership is based on IDs, not state.
        self._require_owner(session)
        del self._players[session.player_id]
        del self._sessions[session.session_id]

    def get(self, player_id: str) -> PlayerPresence | None:
        return self._players.get(player_id)

    def _require_owner(self, session: Session) -> PlayerPresence:
        if not isinstance(session, Session):
            raise TypeError("session required")
        player_id = self._sessions.get(session.session_id)
        if player_id is None or player_id != session.player_id:
            raise PresenceError("session does not own player")
        current = self._players.get(player_id)
        if current is None or current.session_id != session.session_id:
            raise PresenceError("inconsistent ownership")
        return current
