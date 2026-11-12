# Bounded generic stream writer

`server.stream_writer.write_all` writes one payload snapshot through a caller-
supplied send-like callback. It handles partial writes and retries
`InterruptedError`. If the sink stops making progress or raises after a
partial write, `PartialWriteError.bytes_written` tells the caller exactly
where to resume.

## Contract

- The caller supplies the sink; this module opens no socket and starts no
  listener.
- The caller must provide `max_bytes`. This is a local safety bound, not an
  AOW frame or payload limit.
- The input is snapshotted after a size preflight, so later mutation of a
  bytearray or memoryview cannot change bytes halfway through the write.
- Empty payloads are no-ops and do not call the sink.
- A successful call returns the total number of bytes accepted.
- A failed call raises `PartialWriteError` with `bytes_written`,
  `total_bytes`, and the underlying `cause`. The caller owns the original
  payload and may resume from `payload[bytes_written:]` after handling the
  cause.
- Blocking sinks are the intended use. A non-blocking caller must retain the
  payload and resume after a writable notification; this helper does not
  implement an event loop or deadline.

## Protocol boundary

This is generic stream infrastructure only. It does not select an AOW frame
header, length encoding, byte order, compression, encryption, message ID,
handshake, or LoginRequest schema. It is not connected to the localhost mock
or an APK-facing listener. Synthetic tests prove only the helper's write
accounting and failure behavior, not compatibility with the original APK.
