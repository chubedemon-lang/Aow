"""Connected-socket adapter for caller-defined generic frame readers.

This module wraps an already-connected stream socket. It does not create
listeners or connections, select an AOW frame format, or claim APK
compatibility. The caller supplies the frame reader and owns protocol policy.
"""

import math
import select
import socket
import threading
import time

from server.frame_reader import CallbackFrameReader, TruncatedFrame
from server.stream_reader import read_next_frame
from server.stream_writer import write_all


class SocketChannelClosed(RuntimeError):
    """The local channel has been closed and cannot accept new operations."""


class SocketChannelWriteClosed(RuntimeError):
    """The local write direction has been shut down."""


class SocketFrameChannel:
    """Serialize writes and provide one blocking frame reader over a socket.

    The channel takes ownership of the supplied connected stream socket and
    closes it when close() is called. io_timeout_seconds is applied to the
    socket and is an idle timeout for each underlying blocking I/O operation.
    An optional frame_timeout_seconds adds one monotonic deadline for an
    incomplete frame; the deadline survives retries while partial bytes remain.

    reader must be configured by the caller with an explicit probe. This
    class does not define a frame header, length encoding, message ID, AOW
    handshake, or payload schema. The socket must already be connected; this
    class never calls bind(), listen(), accept(), or connect().

    Reads are single-consumer. Writes are serialized so concurrent callers
    cannot interleave their byte sequences. Either peer may half-close its
    write direction while the opposite direction remains usable. A remote
    write-half-close is reported as None after all complete buffered frames
    have been drained; the local write direction remains usable until it is
    explicitly shut down or the channel is closed.
    """

    def __init__(
        self,
        sock,
        reader,
        *,
        io_timeout_seconds=10.0,
        frame_timeout_seconds=None,
        max_read_chunk_bytes=65536,
        max_write_bytes=1024 * 1024,
    ):
        # These objects expose methods that this channel invokes while it
        # owns the I/O lifecycle. Reject subclasses so overridden methods or
        # properties cannot run inside the transport state machine.
        if type(sock) is not socket.socket:
            raise TypeError("sock must be an exact socket.socket instance")
        if type(reader) is not CallbackFrameReader:
            raise TypeError("reader must be an exact CallbackFrameReader instance")
        if (
            type(io_timeout_seconds) is not float
            or not math.isfinite(io_timeout_seconds)
            or io_timeout_seconds <= 0
        ):
            raise ValueError("io_timeout_seconds must be a finite positive float")
        if frame_timeout_seconds is not None and (
            type(frame_timeout_seconds) is not float
            or not math.isfinite(frame_timeout_seconds)
            or frame_timeout_seconds <= 0
        ):
            raise ValueError(
                "frame_timeout_seconds must be None or a finite positive float"
            )
        if type(max_read_chunk_bytes) is not int or max_read_chunk_bytes <= 0:
            raise ValueError("max_read_chunk_bytes must be a positive integer")
        if type(max_write_bytes) is not int or max_write_bytes <= 0:
            raise ValueError("max_write_bytes must be a positive integer")

        if sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise ValueError("sock must be a stream socket")
        try:
            sock.getpeername()
        except OSError as exc:
            raise ValueError("sock must already be connected") from exc

        # Set a finite per-operation timeout before the channel starts using
        # the socket. The caller can choose a smaller value for its deployment.
        sock.settimeout(io_timeout_seconds)

        self._socket = sock
        self._reader = reader
        self._max_read_chunk_bytes = max_read_chunk_bytes
        self._max_write_bytes = max_write_bytes
        self._frame_timeout_seconds = frame_timeout_seconds
        self._pending_frame_deadline = None
        self._state_lock = threading.Lock()
        self._read_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._closed = False
        self._read_eof = False
        self._write_eof = False

    @property
    def closed(self):
        """Whether the local socket has been closed."""
        with self._state_lock:
            return self._closed

    @property
    def read_eof(self):
        """Whether the peer has ended its write direction."""
        with self._state_lock:
            return self._read_eof

    @property
    def write_eof(self):
        """Whether the local write direction has been shut down."""
        with self._state_lock:
            return self._write_eof

    def receive_frame(self):
        """Return one caller-defined frame, None on clean peer EOF.

        Socket timeouts and other receive errors propagate without closing the
        reader or discarding buffered bytes. If frame_timeout_seconds is set,
        its monotonic deadline spans all chunks of one incomplete frame and is
        retained across calls after a partial-frame timeout. The caller should
        close the channel after that deadline expires. A timeout before any
        bytes arrive does not pin a frame deadline. A truncated final frame
        marks the read direction as EOF and raises TruncatedFrame; the caller
        can inspect its original reader to diagnose the retained suffix.
        """
        with self._read_lock:
            with self._state_lock:
                if self._closed:
                    raise SocketChannelClosed("socket channel is closed")
                if self._read_eof:
                    return None

            recv = self._socket.recv
            if self._frame_timeout_seconds is not None:
                if self._pending_frame_deadline is None:
                    self._pending_frame_deadline = (
                        time.monotonic() + self._frame_timeout_seconds
                    )
                deadline = self._pending_frame_deadline

                def recv_before_deadline(max_bytes):
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout("frame receive deadline exceeded")
                        try:
                            readable, _writable, _exceptional = select.select(
                                [self._socket], [], [], remaining
                            )
                        except InterruptedError:
                            continue
                        if not readable:
                            raise socket.timeout("frame receive deadline exceeded")
                        try:
                            return self._socket.recv(max_bytes)
                        except BlockingIOError:
                            continue

                recv = recv_before_deadline

            try:
                frame = read_next_frame(
                    self._reader,
                    recv,
                    max_chunk_bytes=self._max_read_chunk_bytes,
                )
            except TruncatedFrame:
                self._pending_frame_deadline = None
                with self._state_lock:
                    self._read_eof = True
                raise
            except socket.timeout:
                if self._reader.available == 0:
                    self._pending_frame_deadline = None
                raise

            if frame is not None:
                self._pending_frame_deadline = None
            if frame is None and self._reader.closed:
                self._pending_frame_deadline = None
                with self._state_lock:
                    self._read_eof = True
            return frame

    def send_bytes(self, payload):
        """Write one caller-encoded byte sequence completely.

        The caller supplies the complete bytes to send. The channel adds no
        prefix, compression, encryption, or AOW message semantics. If a socket
        error occurs after partial progress, PartialWriteError from the generic
        writer reports the exact accepted offset.
        """
        with self._write_lock:
            with self._state_lock:
                if self._closed:
                    raise SocketChannelClosed("socket channel is closed")
                if self._write_eof:
                    raise SocketChannelWriteClosed(
                        "socket channel write direction is shut down"
                    )
            return write_all(
                self._socket.send,
                payload,
                max_bytes=self._max_write_bytes,
            )

    def shutdown_write(self):
        """Half-close the local write direction without disabling receives.

        The operation waits for any in-progress serialized write to finish.
        It returns True only for the call that performs the transition and
        False when the write direction is already shut down or the channel is
        fully closed.
        """
        with self._write_lock:
            with self._state_lock:
                if self._closed or self._write_eof:
                    return False
                self._socket.shutdown(socket.SHUT_WR)
                self._write_eof = True
                return True

    def close(self):
        """Close the owned socket; safe to call repeatedly.

        Shutdown is attempted first so a blocked receive can be interrupted.
        The method returns True only for the call that performed the close.
        """
        with self._state_lock:
            if self._closed:
                return False
            self._closed = True
            self._write_eof = True

        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._socket.close()
        except OSError:
            pass
        return True

    def __enter__(self):
        if self.closed:
            raise SocketChannelClosed("socket channel is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
