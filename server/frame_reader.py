"""Callback-driven generic frame extraction; no AOW wire format is assumed.

The caller supplies a pure probe that maps a bounded prefix to the total frame
size, or returns None when more prefix bytes are required. This module does not
choose a header, length encoding, byte order, compression, or message schema.
"""

from .stream_buffer import BoundedStreamBuffer


class FrameReaderError(Exception):
    """Base class for callback-driven frame-reader failures."""


class InvalidFrameSize(FrameReaderError):
    """The probe returned a non-positive or non-integer frame size."""

    def __init__(self, value):
        self.value = value
        super().__init__(f"frame probe returned invalid size: {value!r}")


class FrameTooLarge(FrameReaderError):
    """A probed frame exceeds the configured safety limit."""

    def __init__(self, requested, limit):
        self.requested = requested
        self.limit = limit
        super().__init__(f"frame size {requested} exceeds limit {limit}")


class FrameProbeLimitExceeded(FrameReaderError):
    """The probe still needs more prefix bytes at its configured limit."""

    def __init__(self, available, limit):
        self.available = available
        self.limit = limit
        super().__init__(
            f"frame probe needs more than {limit} prefix bytes "
            f"({available} currently buffered)"
        )


class TruncatedFrame(FrameReaderError):
    """EOF arrived before a complete frame could be identified or read."""

    def __init__(self, expected, available):
        self.expected = expected
        self.available = available
        if expected is None:
            message = f"stream ended with an incomplete frame prefix ({available} bytes)"
        else:
            message = (
                f"stream ended: frame needs {expected} bytes, "
                f"only {available} buffered"
            )
        super().__init__(message)


def _positive_int(name, value):
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


class CallbackFrameReader:
    """Extract complete frames using a caller-supplied bounded prefix probe.

    probe(prefix) must return the total frame size (including any prefix) as
    a positive integer, or None only when more prefix bytes are required. It
    must not mutate external state. The probe receives at most
    max_probe_bytes immutable bytes.

    The reader is single-consumer and does not add thread synchronization.
    Its limits are generic resource-safety bounds, not recovered AOW limits.
    """

    def __init__(
        self,
        probe,
        *,
        max_frame_bytes=None,
        max_buffer_bytes=1024 * 1024,
        max_probe_bytes=None,
    ):
        if not callable(probe):
            raise TypeError("probe must be callable")
        _positive_int("max_buffer_bytes", max_buffer_bytes)
        if max_frame_bytes is None:
            max_frame_bytes = min(256 * 1024, max_buffer_bytes)
        else:
            _positive_int("max_frame_bytes", max_frame_bytes)
        if max_probe_bytes is None:
            max_probe_bytes = min(64, max_buffer_bytes)
        else:
            _positive_int("max_probe_bytes", max_probe_bytes)
        if max_frame_bytes > max_buffer_bytes:
            raise ValueError("max_frame_bytes cannot exceed max_buffer_bytes")
        if max_probe_bytes > max_buffer_bytes:
            raise ValueError("max_probe_bytes cannot exceed max_buffer_bytes")

        self._probe = probe
        self._max_frame_bytes = max_frame_bytes
        self._max_probe_bytes = max_probe_bytes
        self._buffer = BoundedStreamBuffer(max_buffer_bytes=max_buffer_bytes)

    @property
    def available(self):
        return self._buffer.available

    @property
    def closed(self):
        return self._buffer.closed

    @property
    def max_frame_bytes(self):
        return self._max_frame_bytes

    def feed(self, data):
        """Append one transport chunk atomically under the buffer limit."""
        return self._buffer.feed(data)

    def close(self):
        """Mark end-of-stream; any incomplete buffered frame becomes an error."""
        self._buffer.close()

    def read_frame(self):
        """Return one complete frame, or None when more input is required.

        Probe errors, invalid sizes, oversized frames, and truncated EOF leave
        buffered bytes untouched so the caller can inspect or terminate safely.
        """
        available = self._buffer.available
        if available == 0:
            return None

        prefix_size = min(available, self._max_probe_bytes)
        prefix = self._buffer.peek(prefix_size)
        frame_size = self._probe(prefix)

        if frame_size is None:
            if self._buffer.closed:
                raise TruncatedFrame(None, available)
            if available >= self._max_probe_bytes:
                raise FrameProbeLimitExceeded(available, self._max_probe_bytes)
            return None

        if type(frame_size) is not int or frame_size <= 0:
            raise InvalidFrameSize(frame_size)
        if frame_size > self._max_frame_bytes:
            raise FrameTooLarge(frame_size, self._max_frame_bytes)
        if frame_size > available:
            if self._buffer.closed:
                raise TruncatedFrame(frame_size, available)
            return None

        return self._buffer.read_exact(frame_size)
