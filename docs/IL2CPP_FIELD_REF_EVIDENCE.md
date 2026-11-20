# IL2CPP v31 FieldRef table evidence

`tools/il2cpp_field_ref_evidence.py` performs a read-only inventory of the
version-31 `Il2CppFieldRef` table in an authorized local APK.

## Layout and limits

- The v31 header's FieldRef offset/size pair is at byte offset `0xB8`.
- Each record is 8 bytes: a signed `TypeIndex` followed by a signed local
  field index.
- The local field index is an offset within the fields declared by the
  referenced type. It is not a global `FieldDefinition` index.
- The reader rejects malformed section bounds, partial records, negative
  indexes, unsupported metadata versions, duplicate requested indexes, and
  caller-defined collection subclasses.

The CLI can report aggregate table shape and selected records with repeated
`--field-ref-index` arguments. It emits no APK bytes, native addresses,
packet data, endpoint values, or extracted assets.

## FieldInfo usage-token correlation

The `correlate_field_info_usage_tokens()` helper joins caller-supplied,
already-observed encoded FieldInfo metadata-usage tokens to this bounded
FieldRef table. The optional `inspect_apk()` argument and repeated
`--field-info-usage-token` CLI option expose the same report for an authorized
local APK, for example:

```sh
python -m tools.il2cpp_field_ref_evidence ./authorized-local.apk \
  --field-info-usage-token 0x80000001 \
  --field-info-usage-token 0x80000005
```

The report preserves token occurrence order and emits only the occurrence
position, resolution status, FieldRef index, TypeIndex, and local field index.
It never emits the encoded token values. Repeated tokens remain repeated
occurrences while the unique resolved FieldRef count is reported separately.
Unresolved or non-FieldInfo usage tokens are not classified further. A decoded
index outside the FieldRef table is explicitly reported as out of range and
is never promoted to a resolved reference. The input collection is bounded
and must be an exact built-in list or tuple of unsigned 32-bit integers.

## Native Il2CppType category correlation

When an authorized offline pass has already produced FieldInfo usage tokens, the analyzer can optionally resolve each resulting FieldRef `TypeIndex` through the ARM64 relocation-backed native `Il2CppType` registration table. Use `--resolve-native-types` together with one or more `--field-info-usage-token` arguments. The reader reopens the same APK through the stable descriptor reader and requires its SHA-256 and metadata bytes to match the first metadata pass before joining the native table.

The output adds only the symbolic native type code/name to each resolved FieldRef occurrence, plus the registration-table count and unique type-index count. It emits no native addresses, raw bytes, encoded usage tokens, or NetworkSettings default values. If no FieldRef occurrence resolves, native parsing is skipped. If the native table is malformed, missing, or ambiguous, the optional join fails closed.

Example:

```sh
python -m tools.il2cpp_field_ref_evidence ./authorized-local.apk \\
  --field-info-usage-token 0x80000001 \\
  --resolve-native-types
```

This resolves only the native type category for the referenced TypeIndex. It does not identify the managed declaring type or field name, prove runtime access, or map a FieldRef to a packet field.

## Evidence boundary

This correlation establishes a static metadata-usage-token to FieldRef
table-coordinate relationship. With `--resolve-native-types`, it additionally
reports only the native type category for each resolved `TypeIndex`. It still
does not identify a managed declaring type or field name, or prove that a
native method uses a particular FieldRef. A FieldRef coordinate is not a packet field,
message ID, serializer order, handshake step, runtime access, wire contract,
or APK/server compatibility result.

The next offline-analysis step is to correlate the resolved native type categories and local field coordinates with a separately verified native callsite, while keeping unresolved usage tokens and ambiguous type-table results explicit. Do not enable the real AOW socket adapter
from this inventory alone. Keep the APK and all extracted metadata/native
assets outside the public repository.
