# Payload-free offline frame audit

`server.offline_frame_audit.audit_packet_fixture_frames` combines the
source-bound private fixture validator with the generic incremental
`LengthFrameDecoder`. It is an offline inspection utility only. It does not
select, infer, or claim an AOW frame format and never opens a socket.

## Required independent inputs

The caller must supply:

- a private fixture record accepted by `validate_packet_fixture`;
- an independently obtained `expected_source_sha256` for the exact authorized
  APK build or local capture;
- an exact `FrameSpec` whose width, byte order, header-inclusion rule and
  resource limits were established independently of the fixture being tested.

Do not derive the expected source digest or the frame specification from
untrusted fixture metadata. A matching source hash and payload hash establish
metadata consistency/integrity only; they do not prove capture origin,
authorization, protocol semantics or APK/server compatibility.

## Output and limits

The function validates the fixture, incrementally decodes it in bounded chunks,
requires clean EOF, and returns an immutable summary containing only:

- source SHA-256, identifying the independently selected source artifact;
- fixture SHA-256, fingerprinting the exact audited byte stream;
- frame count and total wire/header/payload byte counts;
- per-frame payload sizes and SHA-256 digests;
- zero-based frame spans `(frame_start, payload_start, frame_end)`, with
  `frame_end` exclusive, so private capture offsets can be correlated without
  exposing payload bytes.

The fixture digest is an integrity identifier, not proof of capture origin or authorization. It never returns, logs, or stores raw frame payloads. A truncated, malformed,
oversized or over-count fixture raises an error and produces no partial
summary. The caller-selected fixture-byte, chunk and frame-count limits are
resource-safety controls, not recovered AOW limits.

An empty fixture is reported as zero frames and receives the standard SHA-256
digest of the empty byte string. This is a generic byte-stream property, not a
claim that AOW has an empty packet.

## Synthetic tests

All tests use invented local byte sequences. They cover fragmentation,
header-inclusive little-endian framing, empty input, source mismatch,
truncation, oversized lengths, aggregate frame-count limits, invalid resource
limits and damaged configuration snapshots.

Run:

```sh
python -m unittest discover -s tests -p 'test_offline_frame_audit.py' -v
```

Keep APKs, native libraries, packet captures, raw fixture bytes, endpoints,
credentials and player data outside this public repository. Do not connect this
helper to a listener or the real AOW adapter until the complete framing
contract is independently verified from authorized evidence for the same
unchanged APK build and reproduced in a local end-to-end test.
