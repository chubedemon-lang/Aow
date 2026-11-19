"""Synthetic, transport-neutral session phase gate.

This is NOT an AOW handshake or authentication protocol. No APK-derived
message types, keys, tokens, or wire bytes are represented here.
"""


class SessionPhaseError(ValueError):
    """An invalid synthetic session transition or value."""


class SyntheticSessionPhases:
    NEW = "new"
    NEGOTIATED = "negotiated"
    AUTHENTICATED = "authenticated"
    IN_WORLD = "in_world"
    CLOSED = "closed"

    __slots__ = ("_phase", "_player_id")

    def __init__(self):
        self._phase = self.NEW
        self._player_id = None

    @property
    def phase(self):
        """Read-only phase; callers must use validated transition methods."""
        return self._phase

    @property
    def player_id(self):
        """Read-only synthetic player identity."""
        return self._player_id

    def negotiate(self):
        if self._phase != self.NEW:
            raise SessionPhaseError("negotiation requires new session")
        self._phase = self.NEGOTIATED

    def authenticate(self, player_id, verified=False):
        # The caller must independently verify credentials. This gate does
        # not implement authentication and never accepts a password/token.
        if self._phase != self.NEGOTIATED:
            raise SessionPhaseError("authentication out of order")
        if verified is not True:
            raise SessionPhaseError("external verification required")
        if type(player_id) is not int or player_id <= 0:
            raise SessionPhaseError("invalid player id")
        self._player_id = player_id
        self._phase = self.AUTHENTICATED

    def enter_world(self):
        if self._phase != self.AUTHENTICATED:
            raise SessionPhaseError("world entry requires authentication")
        self._phase = self.IN_WORLD

    def leave_world(self):
        if self._phase != self.IN_WORLD:
            raise SessionPhaseError("not in world")
        self._phase = self.AUTHENTICATED

    def close(self):
        self._player_id = None
        self._phase = self.CLOSED
