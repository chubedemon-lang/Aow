"""Synthetic-only bounded length-prefix framing for local fixtures.

NOT an APK-derived AOW protocol. No network I/O.
"""
from dataclasses import dataclass

MAX_FRAME_BYTES = 1024 * 1024


class FrameError(ValueError):
    """Invalid synthetic frame or exceeded resource limit."""


@dataclass
class LengthPrefixDecoder:
    """Incremental four-byte unsigned big-endian framing fixture."""

    max_payload: int = MAX_FRAME_BYTES

    def __post_init__(self):
        if type(self.max_payload) is not int or not 1 <= self.max_payload <= MAX_FRAME_BYTES:
            raise FrameError("invalid maximum payload")
        self._pending = bytearray()

    def feed(self, chunk):
        if not isinstance(chunk, bytes):
            raise FrameError("expected immutable bytes")
        # Process input incrementally: multiple complete frames in one chunk
        # must not be mistaken for a single oversized pending frame.
        frames = []
        offset = 0
        while offset < len(chunk):
            if len(self._pending) < 4:
                take = min(4 - len(self._pending), len(chunk) - offset)
                self._pending.extend(chunk[offset:offset + take])
                offset += take
                if len(self._pending) < 4:
                    break
            length = int.from_bytes(self._pending[:4], "big")
            if not 1 <= length <= self.max_payload:
                self._pending.clear()
                raise FrameError("invalid frame length")
            needed = 4 + length - len(self._pending)
            take = min(needed, len(chunk) - offset)
            self._pending.extend(chunk[offset:offset + take])
            offset += take
            if len(self._pending) == 4 + length:
                frames.append(bytes(self._pending[4:]))
                self._pending.clear()
        return tuple(frames)


def encode_frame(payload, max_payload=MAX_FRAME_BYTES):
    """Encode one synthetic fixture; never infer client compatibility."""
    if type(max_payload) is not int or not 1 <= max_payload <= MAX_FRAME_BYTES:
        raise FrameError("invalid maximum payload")
    if type(payload) is not bytes or not 0 < len(payload) <= max_payload:
        raise FrameError("invalid payload")
    return len(payload).to_bytes(4, "big") + payload
