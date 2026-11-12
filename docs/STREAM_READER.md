# Generic blocking stream reader

`server/stream_reader.py` adapts a blocking recv-like callback to the
caller-supplied `CallbackFrameReader`. It is transport plumbing only and does
not select or infer any AOW wire format.

## Contract

- The caller constructs `CallbackFrameReader` with an independently reviewed
  pure frame-size probe and explicit resource limits.
- The callback receives a positive maximum byte count and must return immutable
  `bytes` no longer than that count.
- `InterruptedError` is retried without changing buffered input.
- Other callback exceptions propagate unchanged. In particular, timeouts and
  non-blocking readiness remain the transport owner's responsibility.
- Already-buffered frames are returned before another receive call, so
  coalesced frames are not discarded.
- A zero-length receive marks EOF. Clean EOF returns `None`; an incomplete
  prefix or body raises `TruncatedFrame` and leaves buffered bytes available
  for inspection.
- Each receive request is bounded by both the caller's `max_chunk_bytes` and
  the frame reader's remaining buffer capacity.

## Scope and safety

This helper does not create sockets, configure deadlines, retry arbitrary I/O
errors, register a listener, select a frame probe, parse message IDs, or perform
compression, encryption, authentication, handshake, or login. Its limits are
generic caller-selected resource bounds, not recovered AOW limits.

Tests use a deliberately synthetic one-byte length probe. They demonstrate
fragmentation, coalescing, interrupted reads, EOF handling, and invalid
callback results only. They are not packet fixtures and do not establish APK
compatibility.

Run the focused tests:

```sh
python -m unittest discover -s tests -p 'test_stream_reader.py' -v
python -m unittest discover -s tests -p 'test_frame_reader.py' -v
```
