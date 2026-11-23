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
- Unshifted 64-bit MOV-register copies that preserve the full value.
- CSEL preserves FieldInfo provenance only when both possible source registers
  carry the same FieldRef coordinate. The condition is not evaluated.
- CSINC, CSINV and CSNEG are recognized as value-transforming conditional-select
  operations. Their FieldInfo source use and any overwritten destination
  provenance are counted, but the transformed destination is never treated as
  an exact FieldInfo value. Only the destination register is cleared, preserving
  unrelated source-register state.
- A W-form CSEL is tracked as truncated provenance because its selected
  32-bit value is zero-extended into the 64-bit destination.
- 32-bit MOV-register copies are tracked as truncated provenance, not as exact
  FieldInfo values, because writing Wd zero-extends the low 32 bits into Xd.
- Relocation-backed 64-bit LDR-literal address loads.
- Exact 64-bit LDR and 64-bit LDP element loads from a supplied eight-byte
  FieldInfo usage cell.
- Relocation-backed 64-bit pointer-slot loads from a statically known address;
  the loaded pointer remains separate from FieldInfo value provenance.
- A resulting FieldRef coordinate remaining in x0-x7 until a uniquely
  resolved direct BL or uniquely resolved BLR-family call.
- Recognized BLR, BLRAA/BLRAB, and zero-modifier authenticated calls exclude
  their target and pointer-authentication modifier registers from ABI arguments.
  An indirect target is attributed only when its tracked address maps to one
  unique metadata-backed method entry. Resolved calls carrying exact FieldInfo
  coordinates receive separate redacted per-call observations; unresolved and
  ambiguous targets remain explicit aggregate counters.

The analysis uses the existing conservative CFG builder. Both conditional
outcomes are considered. State crosses only a unique forward predecessor;
joins and backedges start unknown. Calls clobber caller-saved registers.
Recognized CSINC/CSINV/CSNEG operations clear only their destination while
preserving source registers that are not overwritten. Other unknown
instructions clear tracked state and increment the exact/truncated drop
counters.
A CSEL with differing, missing, or mixed FieldRef coordinates drops the
ambiguous result and increments dedicated source-unmerge counters; a same-coordinate
selection is retained, but W-form results remain truncated. Ambiguous
direct-call targets are not attributed. When an unsupported instruction conservatively clears tracked state, the report counts the drop event and the exact/truncated FieldInfo registers discarded. This distinguishes unsupported data-flow from a path where no FieldInfo provenance was present.

## Output and interpretation

The redacted output includes only relative instruction/block indexes, a
metadata method label, argument-register names, FieldRef table coordinates,
and aggregate direct/indirect call counters. It never emits native addresses,
relocation slots, encoded usage tokens, instruction words, APK bytes, packet
bytes, endpoint values, or player data.

A reported coordinate means only that a value loaded from the specified
static FieldInfo usage cell was still present in an argument register at a
uniquely resolved direct call under the supported value-preserving static
transfer rules. A 32-bit MOV is not value-preserving for an eight-byte
FieldInfo-cell load; calls carrying only that truncated provenance are counted
separately and are not emitted as exact observations. The summary also reports
aggregate coverage counters for direct calls that carry a tracked exact
FieldInfo value but have no unique target association. Such calls are
counted as unattributed (and separately as ambiguous when multiple target
labels remain); they are deliberately not emitted as method observations.
This prevents an empty attributed-observation list from being mistaken for
proof that no FieldInfo-bearing direct calls were encountered. Separate
indirect-call counters identify recognized BLR-family callsites carrying exact
or truncated FieldInfo provenance in x0-x7 after excluding the instruction's
target and authentication-modifier inputs. Those counters do not resolve the
indirect destination and are not per-call method observations.

These counters do not identify a managed declaring type or field name, prove
the call ran, prove the argument's semantic use, identify a packet field,
establish serializer order, or establish a wire contract. The CFG is bounded
and structural; predicates are not evaluated and unsupported instructions can terminate provenance. Such termination is counted separately for exact and truncated FieldInfo registers, but the report intentionally does not expose the unknown instruction word or infer which registers it actually modifies.

Run the synthetic regression vectors with:

```sh
python -m unittest discover -s tests -p 'test_aarch64_field_info_call_arguments.py' -v
```

The helper is not run against an APK by CI. Keep APKs, native libraries,
private static-analysis reports, and all raw captures outside the public
repository.


## LoginRequest-only FieldInfo bridge

The redacted network callsite analyzer keeps the exact
LoginRequestSTSerializer.serialize and
LoginRequestSTDeserializer.deserialize entrypoints in a separate
login_request_callsite_summary; they are not mixed into the transport
callsite_summary or broadened to every login/session serializer.

For each resolved LoginRequest entry window, the separate summary includes
resolved direct/indirect method-call observations and the
FieldInfo-to-call-argument provenance pass. When a statically loaded FieldInfo usage cell can be joined
to a validated FieldRef coordinate and that value remains in x0-x7 at a
uniquely resolved direct BL or uniquely resolved BLR-family target, the report
emits the usage position, FieldRef index, TypeIndex, local field index,
relative instruction index and symbolic target method label.

The BLR-family target resolver accepts only a tracked target-register address
that maps to one unique metadata-backed method entry. Its synthetic tests
cover PC-relative relocation loads and relocation-backed pointer-slot loads,
plus unresolved/ambiguous targets and pointer-authentication input exclusion.
This is a tool-capability change only: no new APK analysis was run and no new
LoginRequest callsite count or wire-contract observation is claimed.

The analyzer also models the CSEL alias conservatively: both source operands
must carry the same FieldRef coordinate before that coordinate is retained.
A W-form selection or any selection involving already-truncated input remains
truncated. If the two source coordinates differ or one source lacks provenance,
the destination is cleared and the unmerged exact/truncated source-register
counts are reported separately. CSEL conditions are decoded only as instruction
structure; their runtime predicates are not evaluated. CSINC/CSINV/CSNEG source
uses, opcode counts, and destination provenance drops are reported separately;
their transformed results are not emitted as FieldInfo coordinates.

This is a new static-analysis bridge for prioritizing private offline review.
It does not resolve the declaring managed field name, prove the call
executes, identify a packet field, establish serializer field order, or
establish a wire contract. Synthetic CI uses fabricated metadata, ELF
relocations and instructions only; the original APK and private reports remain
outside this public repository.
