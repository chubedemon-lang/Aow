# AArch64 delegate method-pointer evidence

**Status: two connection-start delegate targets now resolve to unique IL2CPP MethodDef metadata entries. They remain client-side callback associations, not wire message IDs.**

## Purpose

The authorized original APK's connection-start state machine contains two direct `OnMessageReceivedDelegate::.ctor` callsites followed by `MessageDispatcher.SafeRegister` calls using client-side registration keys 5004 and 5005. Earlier analysis could follow only relocation-backed native pointers and left both delegate targets unresolved.

The analyzer now also recognizes a bounded static-data form used by IL2CPP v27+: a 64-bit load from a non-executable ELF section may contain a zero-extended encoded metadata-usage token. It decodes only an unresolved **MethodDef** token, then resolves its zero-based method index against the same APK's metadata table. It does not interpret MethodRef/generic-method tokens.

## Supported evidence chain

Within a bounded method window, the pass follows only:

- ADR and ADRP address materialization;
- 64-bit ADD-immediate based on a tracked address;
- 64-bit unsigned-offset LDR X from an exact R_AARCH64_RELATIVE relocation;
- 64-bit unsigned-offset LDR X from a unique allocated, non-executable ELF section when the loaded word is a bounded 32-bit metadata-usage token;
- unshifted 64-bit MOV X register copies;
- direct BL calls to a uniquely labeled allowlisted delegate constructor.

For metadata version 27 and later, the analyzer accepts only usage kind 3 (MethodDef) with the unresolved-token bit set, then shifts the encoded index right by one. MethodRef (usage kind 6), other usage kinds, pre-v27 encodings, already-resolved values, missing labels, ambiguous labels, and non-token values remain unresolved or unknown. The version-dependent token behavior is cross-checked against the public [Il2CppInspector MetadataUsage implementation](https://github.com/djkaty/Il2CppInspector/blob/master/Il2CppInspector.Common/IL2CPP/MetadataUsage.cs) and the IL2CPP runtime's [encoded method-index resolution](https://github.com/Rigyuki/il2cpp/blob/main/vm/GlobalMetadata.cpp).

The bounded intraprocedural CFG carries state only through one reachable forward predecessor. Joins and backedges discard state. Direct/indirect calls clobber caller-saved registers; unrecognized instructions clear modeled state. Unsupported forms remain unresolved rather than being guessed.

## Fresh authorized APK result — 2026-11-13

The exact authorized APK fingerprint in the private workspace matched the existing ledger. The analyzer was run read-only against its IL2CPP v31 metadata and ARM64 library. No binary, raw address, encoded token, instruction word, packet byte, endpoint or asset was written to the repository.

The two constructor callsites now resolve as follows:

| Client registration key | Delegate target method | Metadata method kind |
|---|---|---|
| 5004 | `com.geargames.aow.gui.loadingwindow.GUILoadingPvpStartPresenter::OnProgressAnswer/p1` | static |
| 5005 | `com.geargames.aow.gui.loadingwindow.GUILoadingPvpStartPresenter::OnProgressNotification/p1` | instance |

Both method definitions declare one parameter named `message`; their raw parameter type index is retained only in the private analysis. The first constructor call passes a null target, consistent with the static method metadata flag. The second passes a state-machine instance target, consistent with the instance method metadata flag.

This resolves the **client-side listener callback association** for the two registration keys. It does not establish that 5004 or 5005 appears on the wire, identify the message class, or map either key to a packet. The second integer in `Receiver.Cycle` still has an unresolved dictionary owner and semantic role.

## Redacted output

A matching constructor callsite may report:

- `unique_metadata_method` for a unique relocation-backed executable entry;
- `unique_metadata_method_definition` for a unique decoded MethodDef usage token;
- ambiguous or unresolved metadata-method states;
- `unknown` when no supported value reaches the callsite.

The output never includes candidate pointer values, static-data addresses, encoded usage tokens, native addresses, instruction words, APK bytes, packet bytes or endpoint values.

## Interpretation limits

- x2 is a candidate register for the second declared constructor parameter on the observed AArch64 call shape; this remains a static call-shape observation, not a general ABI proof.
- A metadata MethodDef association is not proof that the callback executes at runtime.
- MethodRef/generic-method tokens, runtime-generated methods, thunks, and unsupported pointer materialization remain unresolved.
- Bounded method windows can include cold paths or code after early returns. CFG reachability does not evaluate branch conditions.
- The registration keys remain client-side dispatcher keys. No packet capture or runtime trace links them to transmitted bytes.
- This does not recover framing, message payload fields, handshake/login semantics, or APK/server compatibility.

## Validation

Synthetic tests cover direct relocation-backed pointers, static-data MethodDef tokens, rejected MethodRef/other usage kinds, version and unresolved-token boundaries, ambiguous/malformed metadata, call clobbering, CFG joins, unreachable blocks, invalid inputs, and output redaction. They use fabricated instruction words, metadata labels, and static values only; no APK fixture is included.
