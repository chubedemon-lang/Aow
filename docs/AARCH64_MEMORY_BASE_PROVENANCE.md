# AArch64 memory-base provenance (bounded static evidence)

The native network callsite report includes an optional, redacted intraprocedural
summary of the base register used by supported integer LDR/STR unsigned-scaled, unscaled, and pre/post-indexed
instructions. The analyzer uses absolute addresses internally to follow a
small set of address-building operations, but never emits those addresses,
relocation slots, relocation targets, or raw instruction words.

## Supported provenance

- ADR creates an `adr_derived_address` value using its signed 21-bit byte offset from the instruction PC.
- ADRP creates an `adrp_derived_address` value using its signed 21-bit page offset from the instruction PC page.
- 64-bit ADD (immediate) preserves an existing address and records the latest
  instruction-relative definition.
- 64-bit unflagged SUB (immediate) preserves an existing address with a negative displacement; underflow invalidates only the destination. `SUB Xd, SP, #imm` remains symbolic `stack_pointer` provenance.
- 64-bit `ADD Xd, SP, #imm` marks the destination as `stack_pointer`; later
  64-bit ADD and MOV operations preserve that symbolic class. The concrete
  stack address and displacement are not modeled.
- The unshifted 64-bit MOV register alias copies the abstract value.
- A 64-bit unsigned-scaled or signed unscaled-offset LDR can create a
  relocation_loaded_pointer only when its effective slot exactly matches a caller-supplied
  R_AARCH64_RELATIVE relocation entry.
- A 64-bit PC-relative `LDR Xt, label` literal load is reported separately.
  It creates a relocation_loaded_pointer only when its literal-pool slot
  exactly matches a caller-supplied relative-relocation entry; unresolved
  literal loads invalidate the destination register's prior abstract value.
- An access based on SP is labeled stack_pointer; all other unresolved bases
  are unknown.

The analyzer reuses the repository's bounded intraprocedural CFG. State flows
only through a unique forward predecessor. Conditional branches assume both
in-window outcomes. Backedges and multi-predecessor joins drop register state.
Direct and indirect calls clear modeled caller-saved registers. Unknown
instructions clear the abstract state.

## Output and safety

Each retained memory-access observation contains only:

- instruction-relative index;
- load/store operation, access width, addressing mode, signed access displacement and signed writeback displacement;
- base-register name;
- symbolic base-provenance class;
- relative definition index and derivation depth.

The report includes total, structurally reachable and structurally
unreachable supported immediate access counts, plus separate PC-relative literal
load counts and redacted literal-load observations. Each observation list is
capped at 128 by default and accepts at most 512. The code window is capped at
64 KiB and the supplied relocation map at 200,000 entries.

Absolute addresses, raw instruction words, APK bytes and packet bytes are not
emitted. The caller-supplied relocation map is derived from the private ELF
analysis pass and must remain in memory only.

## Interpretation limits

This is not a full AArch64 emulator, alias analysis, points-to analysis or
runtime trace. It does not model register spills, stack slots, pair/pair/SIMD/atomic memory operations, arbitrary data loads, class
initialization, IL2CPP static-field layout or arbitrary relocation types.
Unknown instructions intentionally discard state. A relocation-loaded pointer
does not identify the pointed-to managed object or field. Stack-pointer-derived
values are symbolic only and are never used for absolute relocation-slot
matching.

Synthetic tests validate instruction decoding, conservative CFG state flow,
redaction and resource limits only. They do not analyze the APK. Do not infer
that any observed base is NetworkSettings.HeaderLength, and do not promote
the receive-side four-byte candidate to a verified frame contract from this
summary. Correlate the same symbolic base chain between NetworkSettings
initialization and Receiver.Cycle, then require a provenance-reviewed
authorized client-side fixture or local runtime trace before enabling an
APK-facing adapter.

Keep the APK, native libraries, raw disassembly and private fixture bytes out
of this public repository.
