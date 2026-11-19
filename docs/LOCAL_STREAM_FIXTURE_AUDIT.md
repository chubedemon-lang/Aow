# Private authorized stream fixture audit

This tool is an offline bridge for a future authorized local test. It does not
make a packet decoder, enable a listener, or establish compatibility.

## Private input only

Create the fixture locally from one authorized test run of the exact unchanged
APK build. Keep the JSON file outside the repository: its hexadecimal chunks
are raw stream bytes and may contain credentials, tokens, player data, or other
private material. Do not attach it to a public issue or pull request.

The schema is intentionally narrow and supports three versions:

- `schema_version`: exact integer `1`, `2`, or `3`.
- `apk_sha256`: lowercase SHA-256 asserted for the tested APK build.
- `client_unchanged`: boolean `true`.
- `capture_kind`: `authorized_local_runtime` or
  `authorized_local_packet_fixture`.
- `streams.server_to_client` and `streams.client_to_server`: ordered arrays
  of non-empty hexadecimal chunks for each already-reassembled directional byte
  stream. Both arrays must contain at least one chunk; a one-way capture is
  incomplete and is rejected rather than presented as a bidirectional exchange.
  These are stream chunks, not individual PCAP packet payloads.
- Schema `1` has no cross-direction chronology. Its report explicitly marks
  exchange order as unavailable.
- Schema `2` additionally requires `io_events`: an ordered array of exact
  objects with `direction`, `offset`, and `length`. Each event describes one
  locally observed I/O range in the concatenated stream for that direction.
  Offsets must cover each directional stream contiguously, without overlap or
  gaps, and every byte in both directions must be covered exactly once. This
  preserves the operator-supplied cross-direction order for later handshake
  review; it does not identify message boundaries.
- Schema `3` uses the same I/O range contract and adds an exact integer
  `elapsed_ns` to every event. The first event must be zero; subsequent values
  must be monotonic non-decreasing and remain within a 24-hour relative span.
  The report exposes only the total event span and maximum inter-event gap,
  not individual times or absolute timestamps.
- For schemas `2` and `3`, event order and range boundaries are
  operator-supplied provenance assertions. They are not cryptographically
  authenticated, do not prove capture timestamps, and must not be inferred
  from PCAP packet segmentation. Use only a local runtime logger or fixture
  exporter that records the actual ordered application I/O operations.
- Do not include endpoint addresses, ports, absolute timestamps, usernames,
  tokens, or other identity fields.

Schematic shape only; the placeholders below are not valid fixture bytes:

```json
{
  "schema_version": 1,
  "apk_sha256": "<expected unchanged APK SHA-256>",
  "client_unchanged": true,
  "capture_kind": "authorized_local_runtime",
  "streams": {
    "server_to_client": ["<private ordered hex chunk>"],
    "client_to_server": ["<private ordered hex chunk>"]
  }
}
```

Schema `2` schematic shape (placeholders are not valid fixture bytes):

```json
{
  "schema_version": 2,
  "apk_sha256": "<expected unchanged APK SHA-256>",
  "client_unchanged": true,
  "capture_kind": "authorized_local_runtime",
  "streams": {
    "server_to_client": ["<private ordered hex chunk>"],
    "client_to_server": ["<private ordered hex chunk>"]
  },
  "io_events": [
    {"direction": "client_to_server", "offset": 0, "length": 12},
    {"direction": "server_to_client", "offset": 0, "length": 8}
  ]
}
```

The example event ranges are illustrative only and must exactly cover the
actual private directional streams. The report exposes event counts and
direction switches; schema `3` also exposes a relative timing span and maximum
inter-event gap. It never emits event offsets, lengths, individual elapsed
values, absolute timestamps, or stream bytes. Schema `1` remains accepted for
older fixtures, but it cannot support cross-direction order or I/O-boundary
correlation.

## Run locally

From the repository root, supply the expected fingerprint independently:

```sh
python -m tools.protocol_fixture_audit \\
  --fixture "$PRIVATE_FIXTURE/authorized-stream.json" \\
  --apk-sha256 YOUR_EXPECTED_64_CHARACTER_LOWERCASE_SHA256
```

The file reader rejects symlinks and non-regular files, uses a no-follow
descriptor opened in non-blocking mode, checks that the file did not change
while being read, and applies a bounded input size. Non-blocking mode is
ignored for regular files but prevents a regular-file-to-FIFO path-swap race
from hanging the CLI before the descriptor type check can reject the FIFO. The JSON parser rejects duplicate keys, unexpected
fields, non-finite constants, and nesting deeper than 64 containers before
constructing the decoded object graph. Invalid filesystem path values are
normalized to a redacted fixture error rather than leaking an operating-system
exception. Both stream directions are summarized under one aggregate 8 MiB
resource budget. The remaining budget is enforced incrementally before each
hex chunk is materialized, so the second direction cannot temporarily allocate
beyond the aggregate cap. This is an audit resource limit, not an AOW protocol
limit. Only the `server_to_client` direction is passed through the isolated
receive-length candidate. By default, the `client_to_server` direction is only summarized
because Sender/Receiver symmetry has not been established. An explicit
operator-selected generic length hypothesis can be tested separately, as
described below; it is never treated as proof of sender symmetry. Schemas
`2` and `3` validate
that ordered I/O ranges cover both directional streams exactly once. Schema
`3` additionally validates relative monotonic timing and reports only an
aggregate span and maximum gap. Schema `1` reports that cross-direction order
was not recorded. No schema allows the audit to interpret handshake or login
messages, and schema `2`/`3` event order remains an unauthenticated operator
assertion rather than independent protocol evidence.

The receive candidate still models only the static four-byte signed
big-endian count branch and rejects the HTTP marker branch. It does not verify
the active runtime branch, full outer frame, compression/encryption placement,
message IDs, handshake, or login. The output contains stream/chunk counts and
at most 4,096 candidate frame sizes; it never emits fixture bytes or the local
file path. If a stream exceeds this
fixed report cap, candidate analysis stops and the result marks the reported
frame count as a lower bound with `frame_sizes_truncated: true`. When the
cap is reached, the reader may consume one additional complete frame to
establish that more frames exist; that frame is not added to the bounded
`frame_sizes` list, but its bytes are included in
`candidate_bytes_consumed`. The report also includes
`unclassified_stream_bytes` and `candidate_stream_fully_consumed`. These
fields account for the complete supplied server-to-client stream, including
bytes after an unsupported marker, an incomplete tail, or data left after the
report cap. `candidate_stream_fully_consumed` means no bytes remain
unclassified; the overall status can still be `candidate_not_recovered` when
the frame-size report cap was reached. They describe only how much input this
candidate parser accepted; they do not validate the real AOW frame boundary.
This is a resource-safety limit for the audit report, not an AOW protocol limit.


## Optional client-to-server length hypothesis

The fixture auditor can test a generic signed big-endian 32-bit length-field
hypothesis against the private client-to-server stream. This is **opt-in** and
does not change the default summary-only behavior.

Use one of the two bounded candidate offsets:

- `0`: test the first four stream bytes as a signed BE32 length.
- `4`: treat the first four bytes as opaque, then test the next four bytes
  as a signed BE32 length. No message-ID meaning is assigned to the opaque
  prefix.

Example local commands:

```sh
python -m tools.protocol_fixture_audit \
  --fixture "$PRIVATE_FIXTURE/authorized-stream.json" \
  --apk-sha256 YOUR_EXPECTED_64_CHARACTER_LOWERCASE_SHA256 \
  --client-to-server-length-offset 0
```

To test the second candidate position, use
`--client-to-server-length-offset 4`. The selected position is an operator
hypothesis, not a recovered Sender field offset. The parser applies caller
resource limits, reports only complete candidate frame sizes and byte
accounting, and never emits stream bytes or offsets.

A complete parse means only that the supplied client-to-server bytes fit the
selected generic hypothesis. It does **not** establish Sender/Receiver
symmetry, prove the first or second integer's semantics, identify a message ID,
confirm compression placement, or verify any AOW frame boundary. The report
always keeps `sender_symmetry_verified`, `wire_contract_verified`, and
`apk_compatible` false. A failed candidate likewise does not disprove other
possible layouts. Keep the private fixture local and review provenance
independently.

## Candidate frame / observed I/O boundary correlation

For schemas `2` and `3`, the redacted report compares cumulative end
positions of complete frames accepted by the isolated receive-length
candidate with the ends of server-to-client I/O observations. It reports only
counts: candidate frame ends aligned with I/O event ends, candidate frame ends
inside an I/O event, I/O event ends aligned with known candidate frame ends,
and I/O event ends without a known candidate frame end.

This comparison can distinguish patterns such as one observed read containing
multiple candidate frames or one candidate frame spanning multiple observed
reads. It is an aggregate diagnostic only. I/O call boundaries are not packet
boundaries, and candidate frame boundaries are not verified AOW message
boundaries. If candidate parsing stops early or reaches the report cap, the
candidate-boundary count is explicitly marked as a lower bound. No offsets are
emitted, and the result never sets `wire_contract_verified` or
`apk_compatible` to true. Schema `1` reports that I/O event boundaries were
not recorded.

## Provenance and limits

The fixture hash and `client_unchanged` value are assertions in the input. The
tool compares the asserted APK hash with the operator-supplied expected hash,
but it cannot authenticate the capture source, prove authorization, or
independently verify that the client was unchanged. Human review of the local
run and fixture provenance is still required before recording
`authorized_local_test` evidence.

A successful candidate parse is only a receive-side candidate observation. It
must not be used to open the AOW adapter gate or claim APK compatibility by
itself. Preserve the private source fixture locally for review; publish only a
separately reviewed, redacted summary if it contains no sensitive metadata.
