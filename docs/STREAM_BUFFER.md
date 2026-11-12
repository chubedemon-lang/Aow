# Bounded generic stream buffer

`server.stream_buffer.BoundedStreamBuffer` is a transport-independent byte
accumulator. It is the first low-level stream primitive for a future adapter,
but it does not open sockets, parse frames, infer message boundaries, or
implement the AOW wire protocol.

## Contract

- `feed(bytes_like)` appends an entire chunk or rejects it; overflow never
  partially mutates the buffer.
- `peek(n)` observes exactly `n` bytes without consuming them.
- `read_exact(n)` consumes only if all `n` bytes are available.
- `read_available(limit)` drains up to a caller-selected number of currently
  buffered bytes.
- `close()` marks producer EOF. Buffered bytes remain readable; a short exact
  read after close raises `UnexpectedStreamEOF`.
- Before EOF, a short exact read raises `NeedMoreData` and leaves the buffer
  unchanged.
- The configured maximum bounds buffered bytes. It is not a protocol frame
  maximum and must not be presented as an AOW packet-size limit.

## Deliberate non-claims

This module does not choose a four-byte header, length byte order, compression,
encryption, message ID, handshake, timeout, or reconnect policy. Those remain
outside the helper until authorized evidence establishes the active wire
contract. The synthetic tests cover fragmentation, coalescing, EOF, atomic
overflow, and input validation only.
