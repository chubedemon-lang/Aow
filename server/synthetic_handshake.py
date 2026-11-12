"""Local synthetic handshake state machine; NOT derived from AOW APK.

No network transport, authentication, or real protocol assumptions. The phase
is exposed as a read-only property so callers cannot accidentally bypass the
transition checks by assigning an established phase directly.
"""
from enum import Enum, auto


class HandshakeError(ValueError):
    """Invalid synthetic handshake transition or input."""


class Phase(Enum):
    NEW = auto()
    CHALLENGED = auto()
    ESTABLISHED = auto()
    CLOSED = auto()


class SyntheticHandshake:
    """Deterministic local fixture with explicit, encapsulated state."""

    __slots__ = ("_phase", "_nonce")

    def __init__(self, phase=Phase.NEW):
        if phase is not Phase.NEW:
            raise HandshakeError("handshake must start new")
        self._phase = Phase.NEW

    @property
    def phase(self) -> Phase:
        """Current phase; transitions must go through this object's methods."""
        return self._phase

    def challenge(self, nonce: bytes) -> None:
        if self._phase is not Phase.NEW:
            raise HandshakeError("challenge out of order")
        if type(nonce) is not bytes or not 8 <= len(nonce) <= 32:
            raise HandshakeError("invalid fixture nonce")
        self._nonce = nonce
        self._phase = Phase.CHALLENGED

    def acknowledge(self, echoed_nonce: bytes) -> None:
        if self._phase is not Phase.CHALLENGED:
            raise HandshakeError("acknowledgement out of order")
        if type(echoed_nonce) is not bytes or echoed_nonce != self._nonce:
            self.close()
            raise HandshakeError("fixture acknowledgement mismatch")
        del self._nonce
        self._phase = Phase.ESTABLISHED

    def close(self) -> None:
        if hasattr(self, "_nonce"):
            del self._nonce
        self._phase = Phase.CLOSED

    @property
    def established(self) -> bool:
        return self._phase is Phase.ESTABLISHED
