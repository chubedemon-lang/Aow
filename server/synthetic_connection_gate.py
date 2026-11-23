"""Synthetic handshake-to-session gate for isolated server lifecycle tests.

NOT an AOW wire adapter, packet decoder, or claim of APK compatibility.
"""
from dataclasses import dataclass
from threading import RLock

from server.synthetic_handshake import (
    HandshakeError,
    Phase as HandshakePhase,
    SyntheticHandshake,
)
from server.synthetic_session import Phase as SessionPhase, SyntheticSession, SessionError


@dataclass(frozen=True, slots=True)
class HandshakeSnapshot:
    """Read-only handshake status; contains no transition methods."""

    phase: HandshakePhase
    established: bool


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """Read-only view of session state; contains no transition methods."""

    phase: SessionPhase
    account_id: str | None
    player_id: str | None
    map_id: int | None


class ConnectionGate:
    """Keep fixture authentication unavailable until fixture handshake succeeds.

    The mutable session and handshake objects stay private. Public properties
    return detached frozen snapshots; all state transitions go through this
    gate so a caller cannot close or advance only one half of the lifecycle.

    A manager may bind one close callback before publishing the gate. Closing
    the gate then notifies that owner exactly once, after releasing the gate
    lock, so related player leases and connection indexes can be cleaned up
    without lock inversion.
    """

    __slots__ = ("_handshake", "_session", "_lock", "_close_callback")

    def __init__(self):
        self._handshake = SyntheticHandshake()
        self._session = SyntheticSession()
        self._lock = RLock()
        self._close_callback = None

    def _bind_close_callback(self, callback) -> None:
        """Bind one lifecycle owner before the gate is exposed to callers."""
        if not callable(callback):
            raise TypeError("close callback must be callable")
        with self._lock:
            if (self._close_callback is not None
                    or self._session.phase is SessionPhase.CLOSED
                    or self._handshake.phase is HandshakePhase.CLOSED):
                raise SessionError("connection close owner cannot be changed")
            self._close_callback = callback

    @property
    def handshake(self) -> HandshakeSnapshot:
        """Return a detached status snapshot, never the mutable handshake."""
        with self._lock:
            return HandshakeSnapshot(
                phase=self._handshake.phase,
                established=self._handshake.established,
            )

    @property
    def session(self) -> SessionSnapshot:
        with self._lock:
            return SessionSnapshot(
                phase=self._session.phase,
                account_id=self._session.account_id,
                player_id=self._session.player_id,
                map_id=self._session.map_id,
            )

    def challenge(self, nonce: bytes) -> None:
        with self._lock:
            self._require_open()
            self._handshake.challenge(nonce)

    def acknowledge(self, nonce: bytes) -> None:
        try:
            with self._lock:
                self._require_open()
                self._handshake.acknowledge(nonce)
        except HandshakeError:
            # Run close notification only after the transition lock has been
            # released; a manager callback may acquire its own lifecycle lock.
            self.close()
            raise

    def authenticate(self, account_id: str) -> None:
        with self._lock:
            self._require_established()
            self._session.authenticate(account_id)

    def select_player(self, player_id: str) -> None:
        with self._lock:
            self._require_established()
            self._session.select_player(player_id)

    def enter_map(self, map_id: int) -> None:
        with self._lock:
            self._require_established()
            self._session.enter_map(map_id)

    def leave_map(self) -> None:
        with self._lock:
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
        callback = None
        with self._lock:
            already_closed = (
                self._session.phase is SessionPhase.CLOSED
                and self._handshake.phase is HandshakePhase.CLOSED
            )
            self._handshake.close()
            self._session.close()
            if not already_closed:
                callback = self._close_callback
                self._close_callback = None

        if callback is not None:
            callback(self)
