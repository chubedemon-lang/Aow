"""Synthetic-only length-prefixed framing for local tests.

This is NOT a recovered AOW wire format. No network operations are performed.
"""
from dataclasses import dataclass

MAX_FRAME_BYTES = 1024 * 1024


class FrameError(ValueError):
    """Invalid synthetic frame or exceeded resource limit."""


@dataclass
class LengthPrefixDecoder:
    """Incremental 4-byte unsigned big-endian length-prefixed decoder."""

    max_payload: int = MAX_FRAME_BYTES

    def __post_init__(self):
        if type(self.max_payload) is not int or not 1 <= self.max_payload <= MAX_FRAME_BYTES:
            raise FrameError("invalid maximum payload")
        self._pending = bytearray()

    def feed(self, chunk):
        if not isinstance(chunk, bytes):
            raise FrameError("expected immutable bytes")
        # Bound buffering even for an incomplete frame or hostile chunks.
        if len(chunk) > self.max_payload + 4 or len(self._pending) + len(chunk) > self.max_payload + 4:
            raise FrameError("buffer limit exceeded")
        self._pending.extend(chunk)
        frames = []
        while len(self._pending) >= 4:
            length = int.from_bytes(self._pending[:4], "big")
            if length == 0 or length > self.max_payload:
                self._pending.clear()
                raise FrameError("invalid frame length")
            if len(self._pending) < 4 + length:
                break
            frames.append(bytes(self._pending[4:4 + length]))
            del self._pending[:4 + length]
        return tuple(frames)


def encode_frame(payload, max_payload=MAX_FRAME_BYTES):
    """Encode one synthetic test frame; never assume client compatibility."""
    if type(max_payload) is not int or not 1 <= max_payload <= MAX_FRAME_BYTES:
        raise FrameError("invalid maximum payload")
    if not isinstance(payload, bytes) or not 0 < len(payload) <= max_payload:
        raise FrameError("invalid payload")
    return len(payload).to_bytes(4, "big") + payload
