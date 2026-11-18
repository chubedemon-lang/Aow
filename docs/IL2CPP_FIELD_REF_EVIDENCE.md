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

## Evidence boundary

This first-stage inventory does not resolve a FieldRef `TypeIndex` through the
native `Il2CppType` registration table, identify the managed owner, or prove
that a native method uses a particular FieldRef. A FieldRef coordinate is not
a packet field, message ID, serializer order, handshake step, runtime access,
wire contract, or APK/server compatibility result.

The next offline-analysis step is to correlate selected FieldRef indexes with
relocation-backed native type records and then with a separately verified
native callsite. Do not enable the real AOW socket adapter from this inventory
alone. Keep the APK and all extracted metadata/native assets outside the public
repository.
