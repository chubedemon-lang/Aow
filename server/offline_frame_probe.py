"""Bounded, explicitly configured synthetic length-frame decoder.

NOT an AOW protocol implementation. Do not infer the wire format from this
module: all parameters must come from independently verified offline evidence.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class FrameSpec:
    length_bytes: int
    byteorder: str
    includes_header: bool = False
    max_payload: int | None = None
    max_chunk_bytes: int = 4 * 1024 * 1024

    def __post_init__(self):
        if type(self.length_bytes) is not int or self.length_bytes not in (1, 2, 4):
            raise ValueError("length_bytes must be 1, 2, or 4")
        if self.byteorder not in ("big", "little"):
            raise ValueError("byteorder must be big or little")
        if type(self.includes_header) is not bool:
            raise ValueError("includes_header must be bool")
        max_declared = (1 << (8 * self.length_bytes)) - 1
        max_representable_payload = (
            max_declared - self.length_bytes
            if self.includes_header else max_declared
        )
        if self.max_payload is None:
            object.__setattr__(
                self, "max_payload",
                min(1024 * 1024, max_representable_payload),
            )
        elif type(self.max_payload) is not int or not (
            1 <= self.max_payload <= min(16 * 1024 * 1024, max_representable_payload)
        ):
            raise ValueError("invalid or unrepresentable max_payload")
        if type(self.max_chunk_bytes) is not int or not (1 <= self.max_chunk_bytes <= 16 * 1024 * 1024):
            raise ValueError("invalid max_chunk_bytes")


class FrameDecodeError(ValueError):
    """Malformed, oversized, or post-EOF frame input."""


class LengthFrameDecoder:
    """Incremental decoder: handles fragmentation and multiple frames per feed."""

    def __init__(self, spec: FrameSpec):
        if not isinstance(spec, FrameSpec):
            raise TypeError("spec must be FrameSpec")
        self.spec = spec
        self._pending = bytearray()
        self._failed = False
        self._finished = False

    @property
    def pending_bytes(self):
        return len(self._pending)

    def feed(self, chunk):
        if self._failed:
            raise FrameDecodeError("decoder failed; create a new instance")
        if self._finished:
            raise FrameDecodeError("decoder already finished; create a new instance")
        if not isinstance(chunk, bytes):
            raise TypeError("chunk must be bytes")
        # Bound the amount copied into the decoder on any one call. A frame
        # larger than this limit may still arrive over multiple feed calls.
        if len(chunk) > self.spec.max_chunk_bytes:
            self._pending.clear()
            self._failed = True
            raise FrameDecodeError("input chunk exceeds maximum")
        # A complete frame may be followed by another frame in one feed.
        self._pending.extend(chunk)
        frames = []
        header = self.spec.length_bytes
        while len(self._pending) >= header:
            declared = int.from_bytes(self._pending[:header], self.spec.byteorder)
            payload_size = declared - header if self.spec.includes_header else declared
            if payload_size < 0 or payload_size > self.spec.max_payload:
                self._pending.clear()
                self._failed = True
                raise FrameDecodeError("invalid declared frame size")
            total = header + payload_size
            if len(self._pending) < total:
                break
            frames.append(bytes(self._pending[header:total]))
            del self._pending[:total]
        # A partial frame cannot exceed its validated maximum, plus header.
        if len(self._pending) > self.spec.max_payload + header:
            self._pending.clear()
            self._failed = True
            raise FrameDecodeError("buffer exceeded maximum")
        return frames

    def finish(self):
        """End the stream; reject and discard any truncated final frame.

        EOF is terminal even when the stream ends cleanly. Create a new
        decoder for a new connection rather than feeding bytes after finish().
        """
        if self._failed:
            raise FrameDecodeError("decoder failed")
        if self._finished:
            raise FrameDecodeError("decoder already finished")
        self._finished = True
        if self._pending:
            self._pending.clear()
            self._failed = True
            raise FrameDecodeError("truncated final frame")
