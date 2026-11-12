"""Bounded generic byte-stream buffer; no AOW frame format is assumed.

This helper only accumulates bytes supplied by an external transport owner.
It does not open sockets, infer message boundaries, parse length prefixes, or
claim compatibility with the original AOW client.
"""


class StreamBufferError(Exception):
    """Base class for bounded stream-buffer failures."""


class NeedMoreData(StreamBufferError):
    """A non-EOF buffer does not yet contain the requested byte count."""

    def __init__(self, needed, available):
        self.needed = needed
        self.available = available
        super().__init__(
            f"need {needed} bytes, only {available} currently buffered"
        )


class UnexpectedStreamEOF(StreamBufferError):
    """The stream is closed before the requested byte count is available."""

    def __init__(self, needed, available):
        self.needed = needed
        self.available = available
        super().__init__(
            f"stream ended: need {needed} bytes, only {available} buffered"
        )


class BufferLimitExceeded(StreamBufferError):
    """Appending a chunk would exceed the configured buffer capacity."""

    def __init__(self, requested, available, limit):
        self.requested = requested
        self.available = available
        self.limit = limit
        super().__init__(
            f"buffer limit {limit} exceeded by {available + requested} bytes"
        )


class StreamClosedError(StreamBufferError):
    """Bytes cannot be appended after the producer has closed the stream."""


class BoundedStreamBuffer:
    """Small bounded accumulator for fragmented or coalesced byte streams.

    `feed` appends one transport chunk atomically. `read_exact` consumes only
    when all requested bytes are available; `peek` never consumes. Before
    close, insufficient data raises :class:`NeedMoreData`; after close it
    raises :class:`UnexpectedStreamEOF`. Buffered bytes remain drainable
    after close.

    The capacity bounds currently buffered bytes. Callers remain responsible
    for socket lifecycle, framing, deadlines, and message-state validation.
    """

    def __init__(self, max_buffer_bytes=1024 * 1024):
        if type(max_buffer_bytes) is not int or max_buffer_bytes <= 0:
            raise ValueError("max_buffer_bytes must be a positive integer")
        self._max_buffer_bytes = max_buffer_bytes
        self._buffer = bytearray()
        self._closed = False

    @property
    def max_buffer_bytes(self):
        return self._max_buffer_bytes

    @property
    def available(self):
        return len(self._buffer)

    @property
    def closed(self):
        return self._closed

    def feed(self, data):
        """Append a bytes-like chunk without partially accepting overflow."""
        if self._closed:
            raise StreamClosedError("cannot feed a closed stream buffer")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("stream chunk must be bytes-like")
        chunk = bytes(data)
        if len(chunk) > self._max_buffer_bytes - len(self._buffer):
            raise BufferLimitExceeded(
                len(chunk), len(self._buffer), self._max_buffer_bytes
            )
        self._buffer.extend(chunk)
        return len(chunk)

    def _validate_count(self, count):
        if type(count) is not int or count < 0:
            raise ValueError("byte count must be a non-negative integer")

    def _require(self, count):
        self._validate_count(count)
        available = len(self._buffer)
        if count > available:
            error = UnexpectedStreamEOF if self._closed else NeedMoreData
            raise error(count, available)

    def peek(self, count):
        """Return exactly count bytes without consuming them."""
        self._require(count)
        return bytes(self._buffer[:count])

    def read_exact(self, count):
        """Consume and return exactly count bytes, or leave state unchanged."""
        self._require(count)
        result = bytes(self._buffer[:count])
        del self._buffer[:count]
        return result

    def read_available(self, max_bytes=None):
        """Consume up to max_bytes currently buffered; None drains all bytes."""
        if max_bytes is None:
            count = len(self._buffer)
        else:
            self._validate_count(max_bytes)
            count = min(max_bytes, len(self._buffer))
        result = bytes(self._buffer[:count])
        del self._buffer[:count]
        return result

    def discard(self, count):
        """Consume exactly count bytes and return the number discarded."""
        self.read_exact(count)
        return count

    def close(self):
        """Mark producer EOF; already-buffered bytes can still be read."""
        self._closed = True
