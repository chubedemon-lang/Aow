# IL2CPP v31 type and field inventory

Run the read-only inventory against an authorized local APK:

    python tools/il2cpp_type_inventory.py /private/path/aow.apk --output /private/path/type-inventory.json

The report contains allowlisted type, field and method associations. It also
records whether a field has a default-value metadata record and preserves the
field and default-value type indexes as separate values.

## Default-value type-index comparison

Each field record now includes
`default_value_type_matches_field_type`:

- `true`: the raw field type index equals the raw default-value type index;
- `false`: the two raw indexes differ;
- `null`: no field-default record exists.

This is only an equality check between metadata indexes. It does **not**
resolve either index to a managed type, prove that two unequal indexes
represent incompatible types, decode the default-data bytes, or establish
the runtime value of a field. In particular, a `false` result must remain
unresolved until the relevant IL2CPP type-registration mapping is recovered.

The inventory intentionally emits no raw default-data bytes. Do not publish
APK files, extracted assets, native addresses, endpoint values, credentials,
or packet captures. Static field metadata is not a wire schema and does not
establish framing, handshake, login order, or APK/server compatibility.
