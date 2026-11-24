"""Blocking receive adapter for the generic callback-driven frame reader.

The caller supplies a recv-like callback and a separately configured
CallbackFrameReader. This module handles partial reads, interrupted syscalls,
and clean/truncated EOF only. It does not open sockets, select timeouts,
define an AOW header, or claim protocol compatibility.
"""

from server.frame_reader import CallbackFrameReader


class StreamReadError(Exception):
    """Base class for generic blocking stream-read adapter failures."""


class InvalidReadChunk(StreamReadError):
    """The receive callback returned an invalid or over-sized chunk."""

    def __init__(self, received, requested, reason):
        self.received = received
        self.requested = requested
        self.reason = reason
        super().__init__(reason)


class ReadBufferFull(StreamReadError):
    """No buffer capacity remains while the frame probe still needs input."""

    def __init__(self, available, limit):
        self.available = available
        self.limit = limit
        super().__init__(
            f"frame reader buffer is full ({available} of {limit} bytes)"
        )


def read_next_frame(reader, recv, *, max_chunk_bytes=65536):
    """Read and return one frame, or None on clean EOF.

    recv(max_bytes) must behave like a blocking socket receive: return bytes
    no longer than requested, return b"" on EOF, or raise an exception.
    InterruptedError is retried without changing reader state. Other callback
    exceptions propagate unchanged, allowing a caller to handle timeouts or
    non-blocking readiness.

    The reader is checked before receiving, so already-buffered coalesced
    frames are returned without another callback invocation. Received chunks
    are bounded by both max_chunk_bytes and the reader's remaining capacity.

    A clean EOF returns None. EOF with a partial prefix/body is reported by
    TruncatedFrame and leaves buffered bytes inspectable. The caller owns
    socket closure, deadlines, and retry policy.
    """
    if not isinstance(reader, CallbackFrameReader):
        raise TypeError("reader must be a CallbackFrameReader")
    if not callable(recv):
        raise TypeError("recv must be callable")
    if type(max_chunk_bytes) is not int or max_chunk_bytes <= 0:
        raise ValueError("max_chunk_bytes must be a positive integer")

    frame = reader.read_frame()
    if frame is not None:
        return frame
    if reader.closed:
        return None

    while True:
        available = reader.available
        capacity = reader.max_buffer_bytes - available
        if capacity <= 0:
            raise ReadBufferFull(available, reader.max_buffer_bytes)
        requested = min(max_chunk_bytes, capacity)

        try:
            chunk = recv(requested)
        except InterruptedError:
            continue

        if type(chunk) is not bytes:
            raise InvalidReadChunk(
                None, requested, "receive callback must return immutable bytes"
            )
        if len(chunk) > requested:
            raise InvalidReadChunk(
                len(chunk), requested, "receive callback exceeded requested byte count"
            )
        if not chunk:
            reader.close()
            return reader.read_frame()

        reader.feed(chunk)
        frame = reader.read_frame()
        if frame is not None:
            return frame
        if reader.closed:
            return None
