"""Local synthetic handshake state machine; NOT derived from AOW APK.

No network transport, authentication, or real protocol assumptions.
"""
from dataclasses import dataclass
from enum import Enum, auto


class HandshakeError(ValueError):
    """Invalid synthetic handshake transition or input."""


class Phase(Enum):
    NEW = auto()
    CHALLENGED = auto()
    ESTABLISHED = auto()
    CLOSED = auto()


@dataclass
class SyntheticHandshake:
    """Deterministic local fixture with explicit state and no secrets."""

    phase: Phase = Phase.NEW

    def __post_init__(self):
        if self.phase is not Phase.NEW:
            raise HandshakeError("handshake must start new")

    def challenge(self, nonce: bytes) -> None:
        if self.phase is not Phase.NEW:
            raise HandshakeError("challenge out of order")
        if type(nonce) is not bytes or not 8 <= len(nonce) <= 32:
            raise HandshakeError("invalid fixture nonce")
        self._nonce = nonce
        self.phase = Phase.CHALLENGED

    def acknowledge(self, echoed_nonce: bytes) -> None:
        if self.phase is not Phase.CHALLENGED:
            raise HandshakeError("acknowledgement out of order")
        if type(echoed_nonce) is not bytes or echoed_nonce != self._nonce:
            self.close()
            raise HandshakeError("fixture acknowledgement mismatch")
        del self._nonce
        self.phase = Phase.ESTABLISHED

    def close(self) -> None:
        if hasattr(self, "_nonce"):
            del self._nonce
        self.phase = Phase.CLOSED

    @property
    def established(self) -> bool:
        return self.phase is Phase.ESTABLISHED
