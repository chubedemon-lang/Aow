# IL2CPP metadata usage token helpers

The offline helper in `tools/il2cpp_metadata_usage_evidence.py` decodes two
versioned metadata-usage token kinds:

- `MethodDef` usage (kind 3)
- `FieldInfo` usage (kind 4)

The upper three bits carry the usage kind and the lower 29 bits carry the
version-dependent source index. For metadata versions before 27, the source
index is unshifted. For version 27 and later, the low bit is a resolution
marker: an odd value is decoded after shifting right by one; an even value is
left unresolved and returns `None`.

## FieldInfo interpretation boundary

`decode_field_info_usage_index()` returns only the index encoded in a
FieldInfo usage token. It does **not** establish that the index is a
`FieldDefinition` index, identify a declaring type, or prove a managed field
is accessed by a particular native callsite. A caller must separately validate
the corresponding metadata FieldRef table entry and its relationship to the
field/type tables before publishing a field association.

The helper contains no APK-specific values and performs no file or network
I/O. Its tests use fabricated 32-bit tokens only. Decoding a token is not
evidence of a packet field, message ID, handshake step, runtime execution, or
APK/server compatibility.
