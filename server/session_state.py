"""Synthetic, transport-agnostic server session lifecycle.

This module does not implement or claim the AOW APK handshake/login protocol.
"""
from dataclasses import dataclass
from enum import Enum


class SessionState(str, Enum):
    CONNECTED = "connected"
    AUTHENTICATED = "authenticated"
    IN_WORLD = "in_world"
    CLOSED = "closed"


class SessionTransitionError(ValueError):
    """Invalid session lifecycle transition."""


@dataclass
class Session:
    session_id: str
    state: SessionState = SessionState.CONNECTED
    player_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.session_id, str) or not (1 <= len(self.session_id) <= 128):
            raise ValueError("invalid session_id")
        if not isinstance(self.state, SessionState):
            raise TypeError("invalid initial state")
        if self.state != SessionState.CONNECTED or self.player_id is not None:
            raise ValueError("sessions must start connected and unauthenticated")

    def authenticate(self, player_id: str):
        if self.state != SessionState.CONNECTED:
            raise SessionTransitionError("authentication requires connected state")
        if not isinstance(player_id, str) or not (1 <= len(player_id) <= 128):
            raise ValueError("invalid player_id")
        self.player_id = player_id
        self.state = SessionState.AUTHENTICATED

    def enter_world(self):
        if self.state != SessionState.AUTHENTICATED or self.player_id is None:
            raise SessionTransitionError("world entry requires authentication")
        self.state = SessionState.IN_WORLD

    def leave_world(self):
        if self.state != SessionState.IN_WORLD:
            raise SessionTransitionError("not in world")
        self.state = SessionState.AUTHENTICATED

    def close(self):
        self.player_id = None
        self.state = SessionState.CLOSED
