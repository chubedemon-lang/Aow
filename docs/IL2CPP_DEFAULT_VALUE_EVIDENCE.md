# IL2CPP v31 compressed default-value evidence

## Scope and method

This is a redacted static-analysis record from the authorized local AOW APK. The APK, metadata member, native library, raw default bytes and native addresses remain outside the public repository.

The analyzer:

1. Parses only IL2CPP metadata version 31 and the ARM64 ELF64 library.
2. Locates the native registration type-pointer table through its count/pointer pair and AArch64 relative relocations.
3. Requires one unique candidate table, a matching registration count, a complete contiguous pointer run, and valid IL2CPP type records for every entry.
4. Resolves the field type index and the default-value type index independently.
5. Accepts only an exact built-in list or tuple of 1–4,096 unique requested type indexes; arbitrary iterators, subclasses, duplicates and oversized requests are rejected before native-table scanning.
6. Decodes 20 allowlisted NetworkSettings I4 defaults: socket timeouts, socket buffer sizes, the header length, zip intermediate buffer size, and receiver/sender encrypted, decrypted, zipped, and unzipped buffer capacities. Values are emitted only in a private report; the public repository records the field allowlist and the two previously documented protocol settings, not the additional APK-derived capacity values.

The native type-pointer table contains 124,985 entries. The report emits the table count and symbolic type names only; it does not emit native addresses or raw bytes.

## Observed fields

| Field | Field type | Default type | Static metadata default |
|---|---|---|---:|
| NetworkSettings.HeaderLength | I4 | I4 | 4 |
| NetworkSettings.ZipIntermediateBufferSize | I4 | I4 | 4096 |

All requested field and default type indexes resolve independently to the native IL2CPP I4 enum. The public regression fixture now covers all 20 allowlisted field names with synthetic values, including one-, two- and four-byte compressed encodings. Other tests cover zigzag negatives, truncated/non-canonical encodings, native-table ambiguity and a complete synthetic APK container.

## Interpretation boundary

The HeaderLength default of 4 is a new static metadata finding. It is consistent with the previously observed Receiver.Cycle path that initially reads four bytes and uses the non-HTTP-marker integer as a subsequent read count. This is stronger corroboration for a four-byte receive-prefix hypothesis, but it is not proof that the static field is applied at runtime, read by the active Receiver path, or defines the complete frame boundary.

This does not establish:

- that every frame is exactly 4 + payload length;
- that the HTTP branch is inactive during gameplay;
- Sender/Receiver framing symmetry;
- compression or encryption placement;
- the byte order of every message field;
- handshake order, LoginRequest field order, or session semantics;
- unchanged-APK compatibility with the reconstructed server.

Keep the real APK and all extracted proprietary assets private. Do not enable the socket adapter based on this metadata default alone.

## Reproduction

Run the tool against an authorized local APK and write its aggregate report to a private path:

    python tools/il2cpp_default_value_evidence.py /private/path/aow.apk --expected-sha256 EXPECTED_SHA256 --output /private/path/default-value-evidence.json

The CLI reads only the metadata and ARM64 IL2CPP members through the existing stable APK descriptor reader. CI uses synthetic fixtures only; it does not contain or download the AOW APK.
