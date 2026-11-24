# Synthetic offline frame probe

`server/offline_frame_probe.py` is a **generic, bounded length-prefix stream decoder** for unit tests and authorized offline research. It is **not** an AOW packet decoder and does not establish that AOW uses a length prefix, particular byte order, header width, encryption, or handshake.

Use it only after offline evidence independently supports a particular `FrameSpec(length_bytes, byteorder, includes_header, max_payload)`. Record sanitized source locators in the evidence ledger. Do not publish APK bytes, proprietary extracted code, endpoints, raw packet captures, or credentials.

Run `python -m unittest discover -s tests -p 'test_offline_frame_probe.py'` from repository root. Tests use fabricated byte streams and cover split/coalesced frames, both endian orders, header-inclusive lengths, malformed sizes, and truncation. No connection to the official service is made.

Before claiming APK compatibility: trace the IL2CPP transport and serialization call path from the authorized APK, confirm framing and login on an isolated local test server, and record end-to-end evidence for the same APK SHA-256.

## Resource bounds

`FrameSpec.max_chunk_bytes` caps each individual `feed()` call (default 4 MiB, hard maximum 16 MiB). A frame may be fragmented across multiple calls, so `max_payload` can exceed the per-call limit. When omitted, `max_payload` defaults to the smaller of 1 MiB and the selected length field's representable payload maximum (subtracting the header width when the length includes the header). An explicit cap from zero through that representable maximum is accepted; a zero cap deliberately permits only empty payloads. An explicit cap above the representable maximum is rejected during construction.

`FrameSpec.max_frames_per_feed` also caps the number of complete frames materialized by one `feed()` call (default 4,096, hard maximum 65,536). This prevents a small-header stream containing many zero-length frames from amplifying one bounded input chunk into an unbounded list of Python objects. If the cap is exceeded, the decoder discards its pending bytes, enters a failed terminal state, and raises `FrameDecodeError`; it never returns a partial frame list. The cap is per call, not a protocol limit or a connection-wide quota.

These are synthetic parser safety limits, not AOW protocol limits.

An oversized feed is rejected and poisons the decoder before the chunk is copied into its internal buffer. Fragmented frames may span multiple feed calls.

## Input type boundary

The decoder accepts only an exact `FrameSpec`, an exact built-in `str` for `byteorder`, and exact built-in `bytes` chunks. Subclasses are rejected before equality, length, or byte-conversion hooks can execute. This keeps the parser's resource and validation checks deterministic; it does not imply anything about the APK's runtime input types or wire contract.

## End-of-stream semantics

`finish()` is terminal. After a clean EOF, later `feed()` calls are rejected so bytes cannot be appended to a closed stream. If EOF arrives with a partial header or body, the decoder clears the pending bytes, poisons itself and rejects subsequent input. Construct a new decoder for a new connection. These are generic stream-lifecycle rules only; they do not describe the AOW client's transport.


## Decoder configuration snapshot

`LengthFrameDecoder` revalidates and copies the exact `FrameSpec` when it
is constructed. Its parsing loop uses scalar values from that validated
snapshot; the `spec` property returns a detached copy for inspection.
Consequently, bypassing `frozen=True` with `object.__setattr__` on the
original configuration or on a returned inspection copy cannot enlarge the
decoder's payload, chunk, or frame-count limits. A damaged configuration is
rejected before the decoder accepts input.

This is generic configuration-integrity hardening for the synthetic decoder.
It does not add an AOW header, frame size, or compatibility claim.

## Exhaustive fragmentation regression

The focused test suite enumerates every possible byte-boundary partition of
two small fabricated streams: a one-byte big-endian payload-length format and
a two-byte little-endian header-inclusive format. It inserts empty feed calls
between chunks and verifies that the same payload sequence is emitted and EOF
completes with no pending bytes.

This is an exhaustive fragmentation regression for those finite synthetic
vectors only. It does not select either layout for AOW, establish sender
symmetry, or prove any APK wire behavior.
