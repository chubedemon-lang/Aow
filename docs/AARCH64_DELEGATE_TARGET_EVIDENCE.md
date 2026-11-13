# AArch64 delegate method-pointer evidence

**Status: analyzer capability only; no callback target or wire message is identified by this change.**

## Purpose

The connection-start metadata inventory identifies two client-side dispatcher registration keys (5004 and 5005) and the OnMessageReceivedDelegate constructor parameters (object, method). The native constructor callsites have not yet been connected to unique callback method targets.

tools/aarch64_delegate_target_evidence.py adds a deliberately narrow, redacted static pass for the next offline investigation. It examines the candidate second managed constructor argument in x2 and reports a method label only when the tracked value exactly matches one unique metadata-backed executable method entry.

## Supported evidence chain

Within a bounded method window, the pass follows only:

- ADR and ADRP address materialization;
- 64-bit ADD-immediate based on a tracked address;
- 64-bit unsigned-offset LDR X when the exact slot has an R_AARCH64_RELATIVE relocation;
- unshifted 64-bit MOV X register copies;
- direct BL calls to a uniquely labeled allowlisted delegate constructor.

The pass uses the existing bounded intraprocedural CFG. Register state crosses a block boundary only through one reachable forward predecessor. Joins and backedges discard state. Direct/indirect calls clobber caller-saved registers; unrecognized instructions clear the modeled state. Unsupported forms remain unresolved rather than being guessed.

## Redacted output

Each matching constructor callsite reports relative instruction/block indexes and one of these states for the configured candidate register:

- unique_metadata_method with a method label;
- ambiguous_metadata_method;
- unresolved_metadata_method;
- unknown when no supported pointer value reaches the callsite.

The output never includes candidate pointer values, native addresses, instruction words, APK bytes, packet bytes, or endpoint values.

## Interpretation limits

- x2 is a candidate register for the second declared constructor parameter on the observed AArch64 call shape; this pass is not an ABI proof.
- A matching metadata method entry is a static pointer association, not proof that the callback executes at runtime.
- A pointer to a thunk, shared generic wrapper, runtime-generated method, or non-relocation-backed target may remain unresolved.
- Bounded method windows can include cold paths or code after early returns. CFG reachability does not evaluate branch conditions.
- This does not map registration keys 5004/5005 to wire message IDs, recover message payloads, establish handshake/login semantics, or prove APK/server compatibility.

## Validation and next step

tests/test_aarch64_delegate_target_evidence.py uses fabricated instruction words and relocation maps only. It covers ADR, ADRP/LDR relocation, register copies, call clobbering, unknown instructions, ambiguous targets, branch joins, unreachable blocks, input validation, and output redaction.

The new analyzer has not been run against the APK in this change. The next offline pass must use the exact authorized APK fingerprint and keep all raw bytes, relocation addresses, native addresses, and disassembly private. If either constructor target remains unresolved, preserve that status and inspect the relevant generic-method/thunk registration path rather than assigning a callback name.
