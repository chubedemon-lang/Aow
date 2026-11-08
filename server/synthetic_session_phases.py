"""Synthetic, transport-neutral session phase gate.

This is NOT an AOW handshake or authentication protocol. No APK-derived
message types, keys, tokens, or wire bytes are represented here.
"""


class SessionPhaseError(ValueError):
    """An invalid session transition or value."""


class SyntheticSessionPhases:
    NEW = "new"
    NEGOTIATED = "negotiated"
    AUTHENTICATED = "authenticated"
    IN_WORLD = "in_world"
    CLOSED = "closed"

    def __init__(self):
        self.phase = self.NEW
        self.player_id = None

    def negotiate(self):
        if self.phase != self.NEW:
            raise SessionPhaseError("negotiation requires new session")
        self.phase = self.NEGOTIATED

    def authenticate(self, player_id, verified=False):
        # The caller must independently verify credentials. This gate does
        # not implement authentication and never accepts a password/token.
        if self.phase != self.NEGOTIATED:
            raise SessionPhaseError("authentication out of order")
        if verified is not True:
            raise SessionPhaseError("external verification required")
        if type(player_id) is not int or player_id <= 0:
            raise SessionPhaseError("invalid player id")
        self.player_id = player_id
        self.phase = self.AUTHENTICATED

    def enter_world(self):
        if self.phase != self.AUTHENTICATED:
            raise SessionPhaseError("world entry requires authentication")
        self.phase = self.IN_WORLD

    def leave_world(self):
        if self.phase != self.IN_WORLD:
            raise SessionPhaseError("not in world")
        self.phase = self.AUTHENTICATED

    def close(self):
        self.player_id = None
        self.phase = self.CLOSED
