# Experimental receive-length framing candidate

**Status: isolated candidate only; not an AOW packet decoder or production adapter.**

## Evidence basis

The static native receive-path trace recorded in [PROTOCOL.md](PROTOCOL.md#native-data-flow-re-verification--2026-11-12) reports:

1. Receiver.Cycle requests an initial four bytes.
2. A primitive `deserializeInt` call reads the four-byte value.
3. The value is compared with the static constant `0x48545450` (the four bytes
   `HTTP` in big-endian order).
4. The equality branch passes that same constant to
   `Receiver.GetHttpMessageResponse`.
5. On the non-marker branch, the decoded value is reused as the next stream-buffer
   read count.

This marker was recovered from a fresh, read-only AArch64 disassembly of
`Receiver.Cycle`. It is a static branch constant only: it does not prove that
the HTTP branch is active during gameplay or recover HTTP response framing.

The primitive codec evidence records `deserializeInt` as a signed 32-bit, big-endian operation. This is enough to model one bounded *candidate branch*, but it does not prove that the complete outer frame is always `4 + count`, that this branch is active for gameplay, or that Sender.Cycle emits a matching structure.

## Isolated implementation

`server.aow_framing_candidate.make_four_byte_length_candidate_probe` returns a callback for the generic `CallbackFrameReader`.

The callback:

- waits for four prefix bytes;
- interprets them as a signed big-endian 32-bit integer;
- defaults to the statically observed marker value `0x48545450`; callers may
  override it for synthetic tests or a separately reviewed client build;
- rejects that marker branch because HTTP response framing is not reconstructed here;
- rejects negative counts and counts above a caller-selected resource limit;
- returns `4 + count` for the non-marker candidate branch.

The payload limit is an operational safety choice supplied by the caller. It is not an observed AOW limit. The helper is not wired to a socket, listener, mock HTTP endpoint, login handler or public service.

## Tests and non-claims

`tests/test_aow_framing_candidate.py` uses fabricated values and a deliberately synthetic marker sentinel. It exercises signed big-endian parsing, short prefixes, invalid/negative/oversized values, marker rejection, fragmentation, coalescing and truncated EOF through the generic frame reader.

The synthetic override `0x13572468` is not an AOW marker. A separate regression
test checks the default against the static `HTTP` marker constant. No APK bytes, native library, endpoint, packet capture, credential or proprietary asset is stored in this repository.

Before using this candidate in an APK-facing adapter, independently verify the marker value, complete sender/receiver relationship, active transport branch, compression/encryption placement and frame boundary with an authorized redacted client-side byte fixture or local runtime trace for the exact APK build. Until then, keep the adapter disabled.
