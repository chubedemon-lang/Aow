# LoginRequest metadata-shape inventory (redacted)

## Scope

This report records a read-only, offline metadata audit of the user-authorized AOW APK. The APK, metadata bytes, native libraries, field names, type indexes, native addresses, endpoint values, and packet data remain private. No APK or extracted asset is part of the repository.

## Reproduced metadata facts

The local audit verified the APK fingerprint against the previously recorded SHA-256 and parsed the IL2CPP v31 metadata tables with exact range checks.

| Item | Result |
|---|---:|
| APK SHA-256 | \`c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e\` |
| Metadata version | 31 |
| \`LoginRequest\` metadata fields | 31 |
| Unique field names | 31 |
| \`LoginRequest\` metadata methods | 65 |
| \`LoginRequestSTSerializer\` metadata methods | 2 |
| \`LoginRequestSTDeserializer\` metadata methods | 2 |
| Serializer metadata parameter count | 4 |
| Deserializer metadata parameter count | 3 |

The field names and field type indexes are deliberately not emitted. The serializer/deserializer parameter counts describe metadata signatures only; they are not payload field counts.

## Interpretation limits

This closes a narrow metadata-table validation gap. It does **not** establish serializer execution order, LoginRequest wire field order, optionality, message IDs, handshake sequence, authentication semantics, framing, compression placement, or unchanged-APK compatibility. The 31 metadata fields must not be treated as 31 serialized payload fields.

The audit tool reads only the metadata ZIP member through one stable, no-follow APK descriptor, verifies an optional expected SHA-256, and emits counts only. It performs no network requests and never modifies the APK.

## Reproduction

\`\`\`sh
python -m tools.loginrequest_metadata_audit /private/path/aow.apk \\
  --expected-sha256 c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e \\
  --output /private/path/loginrequest-metadata-summary.json
\`\`\`

The output is a redacted local summary. Keep it private until reviewed.
