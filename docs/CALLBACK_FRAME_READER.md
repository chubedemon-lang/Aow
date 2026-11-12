# Callback-driven generic frame reader

server.frame_reader.CallbackFrameReader is a generic boundary-extraction helper
built on BoundedStreamBuffer. It does not implement or infer the AOW wire format.

## Probe contract

The caller supplies a deterministic, side-effect-free probe(prefix) callback:

- Return a positive integer for the total size of the first complete frame,
  including any prefix bytes.
- Return None only when the available prefix is insufficient to determine
  that total size.
- Do not consume bytes or mutate external state in the callback.

The reader passes at most max_probe_bytes immutable bytes to the callback.
If the callback still returns None at that limit, the reader raises
FrameProbeLimitExceeded rather than buffering an unbounded header. A size
above max_frame_bytes raises FrameTooLarge. Neither failure consumes input.

read_frame() returns one complete frame, or None when more input is needed.
After close(), an incomplete prefix or body raises TruncatedFrame. The reader
is single-consumer; callers must serialize access if they use threads.

## Limits and deliberate non-claims

The defaults are generic resource-safety values and adapt to a smaller supplied
buffer limit. They are not recovered AOW limits.

This module does not select a header size, length encoding, byte order,
compression, encryption, message ID, handshake, or timeout policy. It must
remain disconnected from the AOW adapter until those details are independently
established from authorized evidence for the same APK build.

The tests use a deliberately synthetic one-byte prefix solely to exercise
fragmentation, coalescing, size validation and EOF behavior. That test format
is not an AOW packet and must not be reused as an AOW protocol assumption.
