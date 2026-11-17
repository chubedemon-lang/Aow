# AArch64 memory-access evidence (tooling only)

The native network callsite report now includes a bounded, redacted summary of
integer LDR/STR instructions using unsigned scaled-immediate addressing. Each
event reports an instruction-relative index, basic-block index, load/store
direction, access width, base/target register names, encoded byte displacement,
and whether its block is structurally reachable in the supported bounded CFG.

## Analysis behavior

The flat helper `summarize_unsigned_immediate_memory_accesses` remains available
for a linear scan. The native callsite report uses
`summarize_control_flow_memory_accesses`, which reuses the repository's
bounded AArch64 branch builder:

- B.cond, CBZ/CBNZ and TBZ/TBNZ contribute both in-window outcomes;
- direct B contributes only its in-window target;
- recognized indirect branches and returns terminate the current path;
- accesses in blocks not reachable from the entry block are marked
  `statically_reachable: false`;
- the report is capped at 128 accesses per method window.

The CFG summary evaluates no condition flags or register predicates. External
branch targets are not followed, unknown branch encodings are not decoded, and
the graph is not a complete disassembly or execution trace. Structural
reachability is not proof that an instruction executes at runtime.

## Interpretation limits

The base register is not resolved to an object, static-fields block, stack
frame, heap allocation, or data cell. The displacement is **not** a managed
field offset. The summary does not decode IL2CPP field metadata, static-field
layout, class initialization, relocation-backed pointer provenance, or values
loaded/stored. SIMD/FP, sign-extending, unscaled, pre/post-indexed, pair, atomic
and other memory forms are omitted.

Synthetic instruction-vector tests validate the decoder, CFG reachability,
report bounds and redacted output only. No APK analysis is performed by tests.
Do not infer that an access belongs to `NetworkSettings.HeaderLength`, and do
not promote the four-byte receive-length candidate to a verified frame
contract from this report.

The next offline analysis step remains to correlate a common base/data-flow
origin and access displacement between `NetworkSettings` initialization and
`Receiver.Cycle`, then corroborate the interpretation with an authorized,
redacted client-side byte fixture or local runtime trace. Keep the APK, native
assets and all private fixture bytes outside this public repository.
