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

## Evidence boundary

This correlation establishes only a static metadata-usage-token to FieldRef
table-coordinate relationship. It does not resolve the native `Il2CppType`
registration table, identify a managed owner, or prove that a native method
uses a particular FieldRef. A FieldRef coordinate is not a packet field,
message ID, serializer order, handshake step, runtime access, wire contract,
or APK/server compatibility result.

The next offline-analysis step is to resolve the referenced `TypeIndex` values
through relocation-backed native type records and then correlate them with a
separately verified native callsite. Do not enable the real AOW socket adapter
from this inventory alone. Keep the APK and all extracted metadata/native
assets outside the public repository.
