# Private authorized stream fixture audit

This tool is an offline bridge for a future authorized local test. It does not
make a packet decoder, enable a listener, or establish compatibility.

## Private input only

Create the fixture locally from one authorized test run of the exact unchanged
APK build. Keep the JSON file outside the repository: its hexadecimal chunks
are raw stream bytes and may contain credentials, tokens, player data, or other
private material. Do not attach it to a public issue or pull request.

The schema is intentionally narrow:

- `schema_version`: integer `1`.
- `apk_sha256`: lowercase SHA-256 asserted for the tested APK build.
- `client_unchanged`: boolean `true`.
- `capture_kind`: `authorized_local_runtime` or
  `authorized_local_packet_fixture`.
- `streams.server_to_client` and `streams.client_to_server`: ordered arrays
  of non-empty hexadecimal chunks for each already-reassembled TCP byte
  stream. These are stream chunks, not individual PCAP packet payloads.
- Do not include endpoint addresses, ports, timestamps, usernames, tokens, or
  other identity fields.

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

## Run locally

From the repository root, supply the expected fingerprint independently:

```sh
python -m tools.protocol_fixture_audit \\
  --fixture "$PRIVATE_FIXTURE/authorized-stream.json" \\
  --apk-sha256 YOUR_EXPECTED_64_CHARACTER_LOWERCASE_SHA256
```

The file reader rejects symlinks and non-regular files, uses a no-follow
descriptor, checks that the file did not change while being read, and applies
a bounded input size. The JSON parser rejects duplicate keys and unexpected
fields. Both stream directions are summarized, but only the
`server_to_client` direction is passed through the isolated receive-length
candidate. The `client_to_server` direction is deliberately not decoded because
Sender/Receiver symmetry has not been established.

The receive candidate still models only the static four-byte signed
big-endian count branch and rejects the HTTP marker branch. It does not verify
the active runtime branch, full outer frame, compression/encryption placement,
message IDs, handshake, or login. The output contains stream/chunk counts and at most 4,096 candidate frame sizes;
it never emits fixture bytes or the local file path. If a stream exceeds this
fixed report cap, candidate analysis stops and the result marks the reported
frame count as a lower bound with `frame_sizes_truncated: true`. This is a
resource-safety limit for the audit report, not an AOW protocol limit.

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
