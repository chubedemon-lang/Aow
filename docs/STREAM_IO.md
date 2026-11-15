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
