# AArch64 FieldInfo-to-call argument provenance

This read-only helper provides one narrow bridge between the static IL2CPP v31
FieldInfo usage-cell inventory and native direct-call argument observations.
It is intended for authorized offline APK analysis only.

## Input contract

The caller supplies:

- One exact, immutable AArch64 method-entry byte window, bounded to 64 KiB.
- Its aligned private start address.
- The existing relocation-backed direct-call target map.
- A private map from each exact eight-byte FieldInfo usage cell address to
  `(usage occurrence position, FieldRef index, TypeIndex, local field index)`.
- Optionally, the existing relocation-slot-to-target map for PC-relative
  literal address loads.

The network callsite analyzer constructs the FieldInfo cell map by sorting
relocation-backed static usage-cell addresses and joining those cells, in the
same order, with the already validated `correlate_field_info_usage_tokens()`
result. Only occurrences whose status is
`field_ref_coordinate_resolved` are supplied to this helper.

## Supported provenance

The bounded intraprocedural pass recognizes:

- ADR and ADRP address formation.
- 64-bit ADD/SUB immediate address adjustment.
- Unshifted 32/64-bit MOV-register copies.
- Relocation-backed 64-bit LDR-literal address loads.
- Exact 64-bit LDR and 64-bit LDP element loads from a supplied eight-byte
  FieldInfo usage cell.
- A resulting FieldRef coordinate remaining in x0-x7 until a uniquely
  resolved direct BL.

The analysis uses the existing conservative CFG builder. Both conditional
outcomes are considered. State crosses only a unique forward predecessor;
joins and backedges start unknown. Calls clobber caller-saved registers.
Unknown instructions and unsupported transformations clear tracked state.
Ambiguous direct-call targets are not attributed.

## Output and interpretation

The redacted output includes only relative instruction/block indexes, a
metadata method label, argument-register names, and FieldRef table coordinates.
It never emits native addresses, relocation slots, encoded usage tokens,
instruction words, APK bytes, packet bytes, endpoint values, or player data.

A reported coordinate means only that a value loaded from the specified
static FieldInfo usage cell was still present in an argument register at a
uniquely resolved direct call under the supported static transfer rules. It
does not identify a managed declaring type or field name, prove the call ran,
prove the argument's semantic use, identify a packet field, establish
serializer order, or establish a wire contract. The CFG is bounded and
structural; predicates are not evaluated and unsupported instructions can
terminate provenance.

Run the synthetic regression vectors with:

```sh
python -m unittest discover -s tests -p 'test_aarch64_field_info_call_arguments.py' -v
```

The helper is not run against an APK by CI. Keep APKs, native libraries,
private static-analysis reports, and all raw captures outside the public
repository.
