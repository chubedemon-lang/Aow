# Generic bounded stream I/O

These helpers are transport plumbing only. They do not open sockets, select a
frame format, infer AOW message boundaries, or establish APK compatibility.

## Accepted input boundary

`BoundedStreamBuffer.feed()` and `stream_writer.write_all()` accept only exact
built-in `bytes`, `bytearray`, and `memoryview` objects. Subclasses are
rejected before length inspection or byte snapshotting. This avoids invoking
caller-defined `__len__` or `__bytes__` hooks while validating untrusted
transport data.

For memoryviews, capacity checks use `nbytes`, not `len()`, because a view
may expose multi-byte elements. Accepted mutable inputs are snapshotted before
being retained or passed to the send callback.

## Write behavior

`write_all()` handles partial blocking writes and retries `InterruptedError`.
If a sink fails after accepting a prefix, `PartialWriteError.bytes_written`
identifies the exact accepted offset; callers own retry scheduling and must
resume with the unsent suffix. The caller supplies `max_bytes`; it is a local
resource limit, not a recovered AOW packet limit.

## Scope and validation

Tests use synthetic bytes only. They cover exact built-in inputs, hostile
subclasses, mutable snapshots, multi-byte memoryviews, partial writes, and
failure offsets. No socket, original APK, packet capture, endpoint, handshake,
or login exchange is involved.

Run:

```sh
python -m unittest discover -s tests -p 'test_stream_buffer.py' -v
python -m unittest discover -s tests -p 'test_stream_writer.py' -v
```

## Connected stream socket wrapper

`server.socket_channel.SocketFrameChannel` wraps an already-connected
`SOCK_STREAM` socket and a caller-configured `CallbackFrameReader`. It does
not create listeners or outbound connections, and it does not select or encode
an AOW frame. The caller still supplies the frame probe and complete bytes to
send.

The channel accepts exact built-in `socket.socket` and
`CallbackFrameReader` instances only; subclasses are rejected so overridden
methods or properties cannot run inside the I/O state machine. It takes
ownership of the socket, applies a finite per-operation socket timeout,
serializes concurrent writes, and permits only one active reader. An optional
`frame_timeout_seconds` adds a monotonic total deadline for one incomplete
frame. The deadline spans fragmented reads and remains pinned across later
`receive_frame()` calls while partial bytes remain, so retrying cannot restart
the budget for that same frame. A timeout before any bytes arrive clears the
pending frame deadline. After a partial-frame deadline expires, the caller
should close the channel rather than retrying the incomplete frame. With this
option omitted, only the per-operation idle timeout applies. Receive timeouts
propagate without closing the reader or discarding buffered input. A truncated EOF raises `TruncatedFrame` and preserves the
incomplete suffix for diagnosis. Either peer may half-close its write direction
while the opposite direction remains usable. Local `shutdown_write()` waits
for an in-progress write, is idempotent, and prevents subsequent sends while
leaving receives available. Full `close()` shuts down both directions to
interrupt a blocked receive. When a close races with a frame-deadline check or
a readiness wait that returns no readable socket, the state lock linearizes
the outcome: a close that wins is reported as an I/O error, while a deadline
that wins is reported as a timeout. A read already past that decision point
may still observe clean EOF or an operating-system socket error as shutdown
completes.

This is generic transport plumbing only. It is not connected to
`server.mock`, an AOW listener, the receive-length candidate, or any login
handler. Do not point the original APK at it. Tests use local
`socket.socketpair()` endpoints and synthetic one-byte test framing only.

Run:

```sh
python -m unittest discover -s tests -p 'test_socket_channel.py' -v
```
