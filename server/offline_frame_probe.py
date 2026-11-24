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
    max_frames_per_feed: int = 4096

    def __post_init__(self):
        if type(self) is not FrameSpec:
            raise TypeError("spec must be the exact FrameSpec type")
        if type(self.length_bytes) is not int or self.length_bytes not in (1, 2, 4):
            raise ValueError("length_bytes must be 1, 2, or 4")
        if type(self.byteorder) is not str or self.byteorder not in ("big", "little"):
            raise ValueError("byteorder must be the exact string big or little")
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
            0 <= self.max_payload <= min(16 * 1024 * 1024, max_representable_payload)
        ):
            raise ValueError("invalid or unrepresentable max_payload")
        if type(self.max_chunk_bytes) is not int or not (1 <= self.max_chunk_bytes <= 16 * 1024 * 1024):
            raise ValueError("invalid max_chunk_bytes")
        if type(self.max_frames_per_feed) is not int or not (
            1 <= self.max_frames_per_feed <= 65536
        ):
            raise ValueError("invalid max_frames_per_feed")


class FrameDecodeError(ValueError):
    """Malformed, oversized, or post-EOF frame input."""


class LengthFrameDecoder:
    """Incremental decoder: handles fragmentation and multiple frames per feed."""

    def __init__(self, spec: FrameSpec):
        if type(spec) is not FrameSpec:
            raise TypeError("spec must be the exact FrameSpec type")
        # frozen=True prevents ordinary assignment, but callers can still
        # bypass it with object.__setattr__. Reconstruct the exact config so
        # mutated or damaged specs are revalidated before any bytes are read.
        try:
            snapshot = FrameSpec(
                spec.length_bytes,
                spec.byteorder,
                spec.includes_header,
                spec.max_payload,
                spec.max_chunk_bytes,
                spec.max_frames_per_feed,
            )
        except AttributeError as exc:
            raise TypeError("spec must be an intact FrameSpec") from exc
        # Keep scalar copies internally. The public spec property below
        # returns a detached value object, so mutating either the caller's
        # original or a returned view cannot expand this decoder's limits.
        self._length_bytes = snapshot.length_bytes
        self._byteorder = snapshot.byteorder
        self._includes_header = snapshot.includes_header
        self._max_payload = snapshot.max_payload
        self._max_chunk_bytes = snapshot.max_chunk_bytes
        self._max_frames_per_feed = snapshot.max_frames_per_feed
        self._pending = bytearray()
        self._failed = False
        self._finished = False

    @property
    def spec(self):
        """Return a detached copy of the validated configuration."""
        return FrameSpec(
            self._length_bytes,
            self._byteorder,
            self._includes_header,
            self._max_payload,
            self._max_chunk_bytes,
            self._max_frames_per_feed,
        )

    @property
    def pending_bytes(self):
        return len(self._pending)

    def feed(self, chunk):
        if self._failed:
            raise FrameDecodeError("decoder failed; create a new instance")
        if self._finished:
            raise FrameDecodeError("decoder already finished; create a new instance")
        if type(chunk) is not bytes:
            raise TypeError("chunk must be the exact built-in bytes type")
        # Bound the amount copied into the decoder on any one call. A frame
        # larger than this limit may still arrive over multiple feed calls.
        if len(chunk) > self._max_chunk_bytes:
            self._pending.clear()
            self._failed = True
            raise FrameDecodeError("input chunk exceeds maximum")
        # A complete frame may be followed by another frame in one feed.
        self._pending.extend(chunk)
        frames = []
        header = self._length_bytes
        while len(self._pending) >= header:
            declared = int.from_bytes(self._pending[:header], self._byteorder)
            payload_size = declared - header if self._includes_header else declared
            if payload_size < 0 or payload_size > self._max_payload:
                self._pending.clear()
                self._failed = True
                raise FrameDecodeError("invalid declared frame size")
            total = header + payload_size
            if len(self._pending) < total:
                break
            if len(frames) >= self._max_frames_per_feed:
                self._pending.clear()
                self._failed = True
                raise FrameDecodeError("frame count exceeds per-feed maximum")
            frames.append(bytes(self._pending[header:total]))
            del self._pending[:total]
        # A partial frame cannot exceed its validated maximum, plus header.
        if len(self._pending) > self._max_payload + header:
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
