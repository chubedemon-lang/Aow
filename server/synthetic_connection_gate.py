"""Synthetic handshake-to-session gate for isolated server lifecycle tests.

NOT an AOW wire adapter, packet decoder, or claim of APK compatibility.
"""
from dataclasses import dataclass

from server.synthetic_handshake import SyntheticHandshake, HandshakeError
from server.synthetic_session import Phase as SessionPhase, SyntheticSession, SessionError


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """Read-only view of session state; contains no transition methods."""

    phase: SessionPhase
    account_id: str | None
    player_id: str | None
    map_id: int | None


class ConnectionGate:
    """Keep fixture authentication unavailable until fixture handshake succeeds.

    The mutable session object and handshake reference are private. The
    handshake property exposes only its validated transition API, while the
    session property returns a frozen snapshot so callers cannot transition
    the underlying session without passing through this gate.
    """

    __slots__ = ("_handshake", "_session")

    def __init__(self):
        self._handshake = SyntheticHandshake()
        self._session = SyntheticSession()

    @property
    def handshake(self) -> SyntheticHandshake:
        return self._handshake

    @property
    def session(self) -> SessionSnapshot:
        return SessionSnapshot(
            phase=self._session.phase,
            account_id=self._session.account_id,
            player_id=self._session.player_id,
            map_id=self._session.map_id,
        )

    def challenge(self, nonce: bytes) -> None:
        self._require_open()
        self._handshake.challenge(nonce)

    def acknowledge(self, nonce: bytes) -> None:
        self._require_open()
        try:
            self._handshake.acknowledge(nonce)
        except HandshakeError:
            self.close()
            raise

    def authenticate(self, account_id: str) -> None:
        self._require_established()
        self._session.authenticate(account_id)

    def select_player(self, player_id: str) -> None:
        self._require_established()
        self._session.select_player(player_id)

    def enter_map(self, map_id: int) -> None:
        self._require_established()
        self._session.enter_map(map_id)

    def leave_map(self) -> None:
        self._require_established()
        self._session.leave_map()

    def _require_open(self) -> None:
        if self._session.phase is SessionPhase.CLOSED:
            raise SessionError("connection is closed")

    def _require_established(self) -> None:
        self._require_open()
        if not self._handshake.established:
            raise SessionError("synthetic handshake not established")

    def close(self) -> None:
        self._handshake.close()
        self._session.close()
