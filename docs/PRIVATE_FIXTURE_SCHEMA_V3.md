# Private stream fixture schema v3: relative timing

This note documents the optional timing extension for the private fixture
auditor. Fixture files remain operator-held and must never be committed.

## Schema

Schema versions 1 and 2 remain unchanged. Version 3 uses the same top-level
keys as version 2 and the same ordered `io_events` list. Each event has exactly
these fields:

- `direction`: `client_to_server` or `server_to_client`
- `offset`: byte offset in the concatenated stream for that direction
- `length`: positive number of observed bytes in this local I/O observation
- `elapsed_ns`: non-negative monotonic elapsed nanoseconds relative to the
  first observation; the first event must be zero

Elapsed values must be non-decreasing and no greater than 24 hours. Equal
values are allowed when the capture clock has insufficient resolution.
Offsets must still cover each directional stream contiguously and exactly.

## Output

The redacted report adds only:

- `event_span_ns`: last elapsed value minus the first
- `max_inter_event_gap_ns`: largest gap between adjacent observations
- `absolute_timestamps_emitted: false`

It does not emit per-event offsets, lengths, elapsed values, wall-clock times,
fixture paths, or payload bytes. The timing summary is explicitly
`relative_monotonic_summary_unverified`.

## Interpretation boundary

An I/O observation is not a packet or message boundary. A read or write can
contain a partial message, several coalesced messages, or transport buffering.
The elapsed span and maximum gap do not identify handshake stages, prove
request/response causality, measure network latency, or authenticate capture
provenance. They are only bounded metadata for later comparison with a
provenance-reviewed authorized local trace.

The tool continues to analyze only the server-to-client stream with the
isolated receive-length candidate. Client-to-server bytes remain summarized,
not decoded, because Sender/Receiver symmetry is unproven. The report must
continue to state `wire_contract_verified: false` and `apk_compatible: false`.

Keep the original APK unchanged. Do not include APKs, native libraries,
captures, endpoints, credentials, player data, or proprietary assets in Git.
