"""Bounded, callback-driven writes to a blocking byte-stream sink.

This module does not open sockets or define an AOW frame format. The caller
supplies a send-like callback and chooses an independent byte limit. Partial
progress is reported so a caller can resume from the exact unsent suffix.
"""


class StreamWriteError(Exception):
    """Base class for generic stream-write failures."""


class WritePayloadTooLarge(StreamWriteError):
    """The immutable payload snapshot would exceed the caller's byte limit."""

    def __init__(self, requested, limit):
        self.requested = requested
        self.limit = limit
        super().__init__(
            f"write payload size {requested} exceeds configured limit {limit}"
        )


class NoWriteProgress(StreamWriteError):
    """The sink reported zero or negative progress for a non-empty write."""

    def __init__(self, count):
        self.count = count
        super().__init__("send callback made no positive write progress")


class InvalidWriteCount(StreamWriteError):
    """The sink returned a count that cannot describe the supplied buffer."""

    def __init__(self, count, remaining):
        self.count = count
        self.remaining = remaining
        super().__init__("send callback returned an invalid byte count")


class PartialWriteError(StreamWriteError):
    """A write failed after zero or more bytes had already been accepted.

    The caller still owns the original payload. Resume with
    `payload[bytes_written:]` after handling the underlying cause.
    """

    def __init__(self, bytes_written, total_bytes, cause):
        self.bytes_written = bytes_written
        self.total_bytes = total_bytes
        self.cause = cause
        super().__init__(
            f"stream write stopped after {bytes_written} of {total_bytes} bytes"
        )


def _snapshot_payload(data, max_bytes):
    if type(max_bytes) is not int or max_bytes < 0:
        raise ValueError("max_bytes must be a non-negative integer")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")

    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if size > max_bytes:
        raise WritePayloadTooLarge(size, max_bytes)

    # Snapshot mutable inputs only after the capacity preflight. bytes() uses
    # the logical bytes of a memoryview, including multi-byte element formats.
    payload = bytes(data)
    if len(payload) != size:
        raise ValueError("bytes-like payload size changed during snapshot")
    return payload


def write_all(send, data, *, max_bytes):
    """Write one immutable snapshot completely through a blocking sink.

    `send` must accept a bytes-like view and return the number of bytes
    accepted, as socket.send does. InterruptedError is retried. Other
    exceptions, invalid counts, and zero progress raise PartialWriteError
    with the exact accepted-byte offset. Non-blocking callers must handle a
    PartialWriteError and resume when writable; this helper has no event loop.

    `max_bytes` is mandatory and caller-selected. It is a local resource bound,
    not a recovered AOW frame or payload limit. Empty payloads return zero
    without invoking the sink.
    """
    if not callable(send):
        raise TypeError("send must be callable")
    payload = _snapshot_payload(data, max_bytes)
    total = len(payload)
    if total == 0:
        return 0

    view = memoryview(payload)
    offset = 0
    while offset < total:
        remaining = total - offset
        try:
            count = send(view[offset:])
        except InterruptedError:
            continue
        except Exception as exc:
            raise PartialWriteError(offset, total, exc) from exc

        if type(count) is not int:
            cause = InvalidWriteCount(count, remaining)
            raise PartialWriteError(offset, total, cause) from cause
        if count <= 0:
            cause = NoWriteProgress(count)
            raise PartialWriteError(offset, total, cause) from cause
        if count > remaining:
            cause = InvalidWriteCount(count, remaining)
            raise PartialWriteError(offset, total, cause) from cause
        offset += count

    return offset
