"""Synthetic handshake-to-session gate for isolated server lifecycle tests.

NOT an AOW wire adapter, packet decoder, or claim of APK compatibility.
"""
from server.synthetic_handshake import SyntheticHandshake, HandshakeError
from server.synthetic_session import SyntheticSession, SessionError


class ConnectionGate:
    """Keep fixture authentication unavailable until fixture handshake succeeds."""

    def __init__(self):
        self.handshake = SyntheticHandshake()
        self.session = SyntheticSession()

    def challenge(self, nonce: bytes) -> None:
        self._require_open()
        self.handshake.challenge(nonce)

    def acknowledge(self, nonce: bytes) -> None:
        self._require_open()
        try:
            self.handshake.acknowledge(nonce)
        except HandshakeError:
            self.close()
            raise

    def authenticate(self, account_id: str) -> None:
        self._require_established()
        self.session.authenticate(account_id)

    def select_player(self, player_id: str) -> None:
        self._require_established()
        self.session.select_player(player_id)

    def enter_map(self, map_id: int) -> None:
        self._require_established()
        self.session.enter_map(map_id)

    def leave_map(self) -> None:
        self._require_established()
        self.session.leave_map()

    def _require_open(self) -> None:
        if self.session.phase.name == "CLOSED":
            raise SessionError("connection is closed")

    def _require_established(self) -> None:
        self._require_open()
        if not self.handshake.established:
            raise SessionError("synthetic handshake not established")

    def close(self) -> None:
        self.handshake.close()
        self.session.close()
