# AArch64 memory-access evidence (tooling only)

The native network evidence report now includes a bounded summary of common
integer LDR/STR instructions using unsigned scaled-immediate addressing.
The scanner is intended to help compare memory-access shapes in the mapped
NetworkSettings initializer, Receiver.Cycle, Sender.Cycle, and selected
serializer entry windows during a future authorized offline APK pass.

## Reported fields

Each reported access contains only:

- relative instruction_index within the bounded method window;
- operation (load or store);
- access width in bytes (1, 2, 4, or 8);
- base and target register names;
- the encoded unsigned byte displacement from the base register.

The summary is capped at 128 entries per method window. It does not emit native
addresses or raw instruction words.

## Interpretation limits

This is a linear instruction scan, not a control-flow graph or execution trace.
A reported instruction can be in a cold or unreachable branch. The analyzer
does not resolve the base register to an object, static-fields block, stack
frame, heap allocation, or data cell. The displacement is **not** a managed
field offset. It does not decode field metadata, static-field layout, class
initialization, relocation-backed pointer provenance, or values loaded/stored.

Only unsigned-immediate integer load/store encodings are included. SIMD/FP,
sign-extending, unscaled, pre/post-indexed, pair, atomic and other forms are
omitted. Absence from the report does not mean a method has no memory access.

Synthetic tests validate instruction decoding and report boundaries only.
No APK analysis is performed by the tests. Do not infer that an access belongs
to NetworkSettings.HeaderLength, and do not use this report to promote the
four-byte receive-length candidate to a verified frame contract.

The next offline analysis step remains to correlate the same base/data-flow
origin and access displacement between NetworkSettings initialization and
Receiver.Cycle, then corroborate the interpretation with an authorized,
redacted client-side byte fixture or local runtime trace. Keep the APK, native
assets and all private fixture bytes outside this public repository.
