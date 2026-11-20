# Native network callsite evidence

**Scope:** authorized, read-only static analysis of the original APK. The APK,
native libraries, raw instructions, native addresses and private analysis
workspace are not included in this repository.

## Reproducibility

- APK SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`
- IL2CPP metadata version: 31
- Metadata method definitions: 197,631
- Metadata images matched to native codegen modules: 165/165
- Native method-pointer slots: 197,631
- Relative-relocation-backed executable targets: 164,023

Run the redacted callsite inventory against an authorized local copy:

```sh
python -m tools.il2cpp_network_callsite_evidence /private/local/aow.apk \
  --expected-sha256 <expected-lowercase-sha256> \
  --output /private/local/network-callsite-evidence.json
```

The optional `--expected-sha256` guard requires an exact 64-character
lowercase SHA-256. The tool hashes the opened APK through its stable descriptor
and rejects a mismatch before parsing ZIP members, preventing an analyst from
accidentally producing a report for a different build. Omitting the option
preserves the existing behavior.

The command is offline and emits method labels, bounded entry-window sizes,
aggregate call counts, and—when relocation-backed FieldInfo usage cells are
found—validated FieldRef table coordinates. Native type-category resolution is
separately opt-in with `--resolve-fieldref-native-types`. It does not emit APK bytes, native
addresses, raw instructions, raw metadata-usage tokens, packet bytes or endpoint
values.

## Static callsite observations

The following direct-call associations were found in bounded native entry
windows for the exact APK fingerprint above:

- Network message processing methods call ReceiverMessageQueue.GetMessage
  and MessageDispatcher.Dispatch.
- Network.SendMessage calls SenderMessageQueue.SendMessageAsync.
- Receiver.Cycle has callsites associated with Socket.Available,
  ClientNetworkStreamBuffer.SetDataAvailable, AbstractClientBuffer.Write,
  SimpleDeserializer.deserializeInt, ClientArrayUtils.ZipDecompress,
  MessageMeta construction, ReceiverMessageQueue.AddMessage,
  SenderMessageQueue.SetConfirmedClientSequenceNumber,
  Receiver.ReadStreamBufferToEnd and Receiver.GetHttpMessageResponse.
- Sender.Cycle has callsites associated with SenderMessageQueue.GetMessage,
  Sender.TrySendHeartbeat, Sender.SerializedMessageTest,
  SimpleSerializer.serializeInt, ClientArrayUtils.ZipCompression,
  ClientStreamBuffer.Write and Sender.GetMessageName.
- Receiver.ReadStreamBufferToEnd calls ClientNetworkStreamBuffer.ReadToEnd.
  Receiver.GetHttpMessageResponse has callsites to BitConverter.GetBytes,
  ASCII encoding and ClientNetworkStreamBuffer.ReadToEnd.

These are method-call associations in bounded native entry windows. They
identify useful next methods to inspect, but do not establish a complete
control-flow graph or prove that every call executes on every message.

## Relocation-backed FieldInfo usage cells

The analyzer also scans relocation-referenced eight-byte cells in the ELF
`.data` and `.data.rel.ro` sections for resolved v31 FieldInfo metadata-usage
tokens. When such cells are found, their token indexes are joined to the
validated metadata FieldRef table. The report preserves deterministic cell
order and emits only FieldRef index, TypeIndex and the field index local to that
type; it never emits the encoded token or the cell address. By default, this
stops at FieldRef coordinates. The opt-in `--resolve-fieldref-native-types`
flag also resolves each referenced TypeIndex through the relocation-backed
ARM64 `Il2CppType` registration table and adds only the symbolic native type
category and aggregate table counts. In selected method windows it also marks
memory-access ranges that overlap one of those static FieldInfo cells using a
boolean and an aggregate count; no cell address is emitted. This is a static
instruction-to-cell overlap, not proof that the loaded value is consumed as a
packet field. It does not identify a managed declaring type or field name.

This is a whole-section static-data inventory, not a use-def chain. A matching
cell does not prove that `Receiver.Cycle`, `Sender.Cycle` or any selected
network method reads it. A FieldRef coordinate is not a managed declaring-type
name, a native field offset, or proof of runtime access. If a token is found but
the FieldRef table is malformed, analysis fails closed rather than dropping the
correlation.

## What this does and does not establish

The static callsites support the existence of socket-availability checks,
buffer operations, integer primitive reads/writes, compression/decompression
helpers, message metadata construction and queue handoff paths in the native
network code.

They do **not** establish:

- the effective runtime value or semantics of NetworkSettings.HeaderLength;
- the actual packet header layout, length-prefix convention or framing;
- whether the integer calls are lengths, sequence numbers, message IDs or other
  values;
- the compression algorithm, activation flag, byte range or exact placement in
  the transmitted stream;
- the active transport or whether the HTTP-named path is used for gameplay;
- message IDs on the wire, LoginRequest field order, handshake sequence,
  authentication semantics or APK/server compatibility.

The analyzer bounds each method window at the next distinct executable entry
in the same ELF section, with a maximum window size. Such a window can include
multiple branches, cold paths, shared code or instructions after an early
return. Direct-call counts are not a statement of execution order. Indirect
calls are resolved only for a narrow relocation-backed ADRP/ADD/LDR chain
with optional unshifted MOV X-register copies before BLR or BR, and a unique
metadata method target; all other indirect calls remain unresolved.

## Next native investigation

1. Inspect the native data flow around Receiver.Cycle's integer reads and
   ClientNetworkStreamBuffer.SetDataAvailable/AbstractClientBuffer.Write.
2. Inspect Sender.Cycle around integer writes, ClientStreamBuffer.Write and
   ZipCompression.
3. Trace NetworkSettings initialization and the concrete read sites for
   HeaderLength before assigning any framing meaning.
4. Recover LoginRequest field order only from validated native data flow and
   corroborating authorized client-side evidence.

No extracted endpoint is contacted. No official server is probed. The real
APK adapter remains blocked until the actual byte stream can be reproduced
from an authorized test-client log or redacted packet fixture.


## Receiver/Sender stream-length candidate — 2026-11-11

A second read-only pass was run against the same locally held APK fingerprint above. The file was re-materialized privately, its SHA-256 was recomputed and matched, and the ZIP archive integrity check completed without a bad member. The local disassembly tool was LLVM llvm-objdump 17.0.0. No APK bytes, native addresses, raw instructions or private captures were added to this repository.

The bounded Receiver.Cycle entry window contains this static call/data-flow sequence:

1. A ClientNetworkStreamBuffer.SetDataAvailable call is supplied the immediate value 4.
2. AbstractClientBuffer.Write(sourceBuffer, count) is then called with count = 4.
3. SimpleDeserializer.deserializeInt(buffer) reads an integer from the resulting buffer.
4. One branch compares the returned value with an HTTP marker. In the non-marker branch, the returned integer is reused as the next SetDataAvailable value and AbstractClientBuffer.Write count.
5. The same entry window later contains another deserializeInt call, ClientArrayUtils.ZipDecompress, MessageMeta construction and receiver queue handoff callsites.

The bounded Sender.Cycle entry window contains callsites to ClientArrayUtils.ZipCompression, SimpleSerializer.serializeInt, ClientNetworkStreamBuffer.SetDataAvailable and ClientStreamBuffer.Write. The independently inspected primitive helper body supports a 32-bit big-endian representation for serializeInt.

**Interpretation: framing is now a candidate, not unknown with no lead.** Together, the receive-side fixed four-byte read followed by an integer-driven second read, and the send-side integer serialization plus stream writes, are consistent with a four-byte big-endian length-prefix path. The HTTP-marker branch indicates a special case in the receive path.

This does not yet prove that the field named NetworkSettings.HeaderLength is the source of the four-byte constant, that the serialized integer is definitively the payload length on every path, or that the observed branch is used in every session. The metadata field exists, but its runtime value and direct storage/access relationship remain unresolved. The entry windows are bounded by adjacent executable entries, not formal function boundaries; they may contain cold branches or shared code. No runtime packet, handshake, login or client/server exchange was observed.

Accordingly, the evidence ledger may record a framing candidate for follow-up, but must not promote framing to verified or enable an AOW transport adapter. The next proof still requires an authorized, redacted client-side fixture or local runtime trace that matches the unchanged APK and reproduces the complete byte stream. No extracted endpoint was contacted.


## Redacted small-immediate argument observations — tooling only

The offline network callsite inventory now optionally reports small constants
that a conservative linear scan can still prove in AArch64 argument registers
x0-x7 immediately before selected direct calls to the stream-buffer methods
listed by the tool.

The scan supports MOVZ/MOVN/MOVK, the unshifted MOV-register alias (ORR with XZR and LSL #0), and ADD-immediate register updates. Any
unrecognized instruction clears its abstract register state; an unconditional
branch clears all state; a direct call clears caller-saved registers. Ambiguous
targets and values above 0xffff are omitted. Output contains method labels,
linear-window call ordinals and small register constants only—never native
addresses, instruction bytes or APK data.

This is **not** a control-flow graph, a complete AArch64 emulator, an ABI proof,
or a runtime trace. A reported x-register constant is only a statically
recoverable value at one direct-call site inside a bounded entry window. It
does not establish the parameter's semantic name, whether the path executes,
whether the call is reachable, or whether a value is a frame length. The
existing framing candidate remains unverified and the real APK adapter stays
disabled pending an authorized, redacted client-side fixture or local runtime
trace.


## Ordered relocation-backed indirect-call labels — tooling only

The redacted callsite summary now includes an ordered list of uniquely
resolved relocation-backed indirect method labels for each bounded entry
window. This preserves the order among the indirect BLR events that the narrow
ADRP/ADD/LDR resolver can prove, while continuing to omit raw native addresses,
instruction bytes and APK data.

The list is deliberately partial: unresolved and ambiguous indirect calls are
counted separately and omitted from the sequence. Direct BL calls are reported
by the existing direct-call summaries and are **not interleaved** into this
indirect-only list. The result is still a linear-window observation, not a
control-flow graph, a complete serializer field order, or proof that every
listed call executes on a real login path. It is useful for selecting the next
offline inspection targets, but cannot establish the LoginRequest wire schema
or enable the APK adapter.


## Unshifted MOV X-register copy support — tooling only

The conservative indirect-call resolver also recognizes the exact AArch64
64-bit MOV-register alias `ORR Xd, XZR, Xm, LSL #0`. A tracked pointer value
may be copied between X registers before the relocation-backed indirect call.
Writing to XZR has no effect on tracked state; reading XZR produces the known
zero value, which is not promoted to a metadata method target. Unknown source
registers invalidate only the destination value. Shifted ORR forms, W-register
moves, and other variants remain unsupported and therefore clear tracked
state as unrecognized instructions.

Synthetic instruction-vector tests cover copied pointers, unknown sources,
zero-register behavior and rejection of shifted/non-64-bit aliases. This is a
tooling capability only; no new APK pass or runtime trace is implied.


## ADR-relative pointer candidate support — 2026-11-12

The offline analyzer now recognizes the AArch64 `ADR` PC-relative address
instruction separately from page-relative `ADRP`. In synthetic instruction
fixtures it can follow an `ADR` address through the existing optional
64-bit `ADD`, relocation-backed `LDR X`, optional `MOV Xd, Xm`, and
`BLR`/`BR` path. A target is still reported only when the loaded pointer
has an `R_AARCH64_RELATIVE` relocation and uniquely matches a metadata-backed
executable method entry.

This is a decoder/tool capability covered by synthetic instruction tests.
No new APK bytes were read or analyzed for this change. It does not establish
that the original APK uses an ADR-based pointer chain, and it does not change
the framing, compression, message-ID, handshake, or LoginRequest confidence
levels. Raw addresses and instruction words remain excluded from reports.


## Fresh APK byte and native data-flow re-verification — 2026-11-12

The authorized local APK was re-materialized privately. Its SHA-256 matched the fingerprint at the top of this document; the full ZIP CRC test passed for all 7,368 entries. The metadata remains IL2CPP v31 and the arm64 library remains an ELF64 little-endian AArch64 shared object. No APK bytes, extracted native library, raw instructions, native addresses, endpoint values or packet captures were committed.

The receive-side call arguments were rechecked, not merely counted. In the bounded `Receiver.Cycle` window:

- `ClientNetworkStreamBuffer.SetDataAvailable` receives a statically known count of **4** at the initial read setup.
- `AbstractClientBuffer.Write` receives a statically known count of **4** for that first copy.
- The next direct call is `SimpleDeserializer.deserializeInt`.
- The returned integer is compared with the HTTP marker; in the non-marker branch, that value is passed onward as the next read/copy count.
- The same window contains a later integer read, `ZipDecompress`, `MessageMeta` construction and queue handoff.

The helper implementation confirms the count argument is stored by `SetDataAvailable` and used by `AbstractClientBuffer.Write` for its buffer operation. `deserializeInt` composes two 16-bit reads high-half first; the 16-bit helper composes two one-byte reads high-byte first. The matching serializer path writes high half/high byte before low half/low byte. This is static evidence for a big-endian 32-bit integer primitive.

The bounded `Sender.Cycle` window has two `serializeInt` callsites, one `ZipCompression` callsite, one buffer-length setup, and two `ClientStreamBuffer.Write` callsites. The callsite sequence is not a complete control-flow trace, so neither integer is assigned a definitive message-ID, sequence-number or frame-length meaning.

The bounded LoginRequest serializer window contains direct calls to primitive helpers with counts: 19 integer, 16 string, 2 long and 1 boolean. The corresponding deserializer window contains 14 integer, 16 string, 2 long and 1 boolean direct helper calls. The integer-count difference remains unexplained. No field order is inferred from these counts.

**Confidence update:** the receive-side four-byte big-endian length-prefix candidate is now supported by fixed-count argument evidence and the primitive helper bodies, rather than method names alone. It is still not a verified complete wire frame or a runtime observation. The relationship to the `NetworkSettings.HeaderLength` field, active branch behavior, compression/encryption placement, message IDs, handshake and LoginRequest field order remain unresolved. The AOW transport adapter must remain disabled pending an authorized, redacted client-side byte fixture or local runtime trace.


## Bounded CFG-aware small-argument analysis — 2026-11-12

The separate tools/aarch64_call_argument_evidence.py pass now builds a bounded
intraprocedural control-flow graph for B.cond, CBZ/CBNZ, TBZ/TBNZ, direct B,
BR and RET. It skips unreachable fallthrough bytes after unconditional exits,
preserves constants across a unique forward predecessor, and drops state at
multi-predecessor joins and backedges. BL and BLR calls clobber the modeled
caller-saved registers. Unknown instructions clear the abstract state.

Observations are restricted to uniquely resolved direct BL calls matching an
explicit allowlist. They include relative basic-block and instruction indexes;
no native addresses, instruction words, APK bytes or packet data are emitted.
The method window is capped at 64 KiB. The synthetic tests cover conditional
paths, joins, unreachable blocks, returns, indirect branches, indirect calls,
out-of-window branches and backedges.

This is a conservative static register-value observation, not a full ABI or
data-flow proof. It does not establish serializer field order, message IDs,
handshake, framing or APK/server compatibility. See
[AArch64 argument data-flow limits](AARCH64_ARGUMENT_DATAFLOW.md).


## CFG-aware relocation-backed indirect-call targets — tooling only

The control-flow block summary now resolves plain BLR call targets using the
same bounded intraprocedural graph that labels reachable and unreachable
blocks. It follows only the narrow ADR/ADRP, 64-bit ADD-immediate,
relocation-backed LDR X and unshifted MOV X-register subset.

Abstract pointer state crosses a block boundary only when there is exactly
one reachable forward predecessor. State is discarded at multi-predecessor
joins, backedges, unreachable incoming paths, direct/indirect calls and
unrecognized instructions. Unresolved or ambiguous indirect targets remain
unresolved; raw addresses and instruction words are never emitted.

The separate linear callsite summary remains explicitly linear and is not an
execution trace. Indirect BR tail-edge discovery still uses its existing
narrow relocation-backed scan; this change does not claim to resolve arbitrary
virtual calls, authenticated indirect calls, runtime-computed pointers or
conditional outcomes.

Synthetic instruction-vector tests cover two mutually exclusive branch paths
that resolve to different helper labels and a multi-predecessor join where the
target must remain unresolved. This is analyzer capability only: no new APK
bytes were read, no native pass was run, and no framing, message ID, handshake,
LoginRequest field order or APK compatibility claim is added.


## NetworkSettings initialization callsite roots — 2026-11-13 (tooling only)

The redacted native-method callsite inventory now includes the exact
`NetworkSettings::.cctor` and `NetworkSettings::.ctor` entry windows alongside
the existing Receiver, Sender, dispatcher and MessageHelper roots. This keeps
the initializer call paths visible in future authorized offline runs rather
than mapping the methods only as executable entrypoints.

A synthetic regression test verifies that both initialization methods appear
as separate callsite records and that the report still omits native addresses
and raw instructions.

**This change does not resolve static-field loads/stores, decode the
`HeaderLength` field-default record, determine its effective runtime value, or
prove that the field supplies the four-byte receive read.** The current
callsite summary is bounded and redacted; it is not a control-flow proof.
Continue to treat `HeaderLength` use and the sender/receiver framing
relationship as unresolved until a private APK pass or authorized local
fixture establishes them.


## Fresh authorized offline APK re-verification — 2026-11-14

The original APK was re-materialized into a private workspace and read successfully. Its SHA-256 matched the established fingerprint; the ZIP integrity test passed for all 7,368 entries, with no duplicate entry names. The IL2CPP metadata is version 31 and contains 31,187 type definitions, 197,631 method definitions and 165 metadata images. The bounded AArch64 codegen pass matched all 165 image names to native codegen module records and resolved 164,023 relocation-backed executable method-pointer slots. This is static registration evidence only; no binary, extracted asset, raw address, instruction word, endpoint or packet data was committed.

### Receiver and message-type lookup path

A fresh bounded disassembly of `Receiver.Cycle` confirms two direct `SimpleDeserializer.deserializeInt` callsites:

- The first follows a four-byte receive-buffer setup/copy. Its result is used as the subsequent read/copy count on the non-HTTP branch. Together with the previously checked primitive helper bodies, this supports a four-byte big-endian receive-length candidate, not a complete verified frame.
- The second integer is passed as the key argument to a lookup helper using an object loaded from static state. The lookup occurs before the decompression path, `MessageMeta` construction and receiver-queue handoff. The lookup target and object owner are not yet resolved, so this integer is **not** labeled a numeric wire message ID.

The metadata confirms that `MessageHelper` declares both `m_messageTypeByMessageClass` and `m_messageClassByMessageType`. The current native data-flow pass does not yet prove that the receiver-side lookup object is either of those exact fields. The owner-resolution step remains open.

### Login and session-restore serializer callsites

The fresh bounded entry-window pass reproduced the existing LoginRequest direct primitive-helper counts:

- Serializer: 19 `serializeInt`, 16 `serializeString`, 2 `serializeLong`, 1 `serializeBoolean`.
- Deserializer: 14 `deserializeInt`, 16 `deserializeString`, 2 `deserializeLong`, 1 `deserializeBoolean`.

It also produced the following SessionRestoreRequest counts:

- Serializer: 5 `serializeInt`, 2 `serializeString`.
- Deserializer: 4 `deserializeInt`, 2 `deserializeString`.

These are direct helper **callsite counts in bounded native entry windows**, not runtime execution counts, field counts, serializer order, or a reconstructed message schema. Branches and helper indirection can affect the relationship between callsites and serialized values. No LoginRequest or SessionRestoreRequest field order is inferred.

### Remaining limits

The `NetworkSettings` initializer is mapped, but the native field-offset relationship needed to attribute a runtime value to `HeaderLength` is still unresolved. The receiver lookup object owner, numeric wire IDs, compression/encryption placement, complete sender/receiver symmetry, LoginRequest field order, handshake order and authentication ownership remain unverified. No authorized client-side wire fixture or end-to-end test with the unchanged APK was available in this pass.

The transport adapter therefore remains disabled. This re-verification adds static evidence and narrows the next tracing task; it does not establish APK/server compatibility.


## Startup delegate method association — 2026-11-14

The unchanged APK's `<StartConnectToServer>d__12.MoveNext` entry window
contains two `OnMessageReceivedDelegate::.ctor` calls followed by
`MessageDispatcher.SafeRegister(type, listener)` calls. The method argument
is loaded through a relocation-backed global pointer and then from a
file-backed static data cell. For this metadata v31 build, the encoded
MethodDef usage token is decoded with the v27+ low-bit marker before looking
up the metadata method definition and its codegen entrypoint.

The redacted analyzer now associates the two startup delegates with:

- `GUILoadingPvpStartPresenter.OnProgressAnswer(message)`: static method; its
  mapped entry window is a single return instruction.
- `GUILoadingPvpStartPresenter.OnProgressNotification(message)`: instance
  method; its entry window contains a message-type check and an indirect call.

Both methods have one parameter named `message`, matching the metadata
signatures of `OnMessageReceivedDelegate.Invoke(message)` and
`MessageDispatcher.Dispatch(message)`. `SafeRegister` metadata names its
parameters `type` and `listener`. The numeric registration constants are
intentionally omitted from public output and are not identified as wire
message IDs.

This is static delegate-to-method association at the registration sites, not
proof of runtime execution, server semantics, a complete message schema,
handshake order, or APK/server compatibility.


## LoginToBattleRequest serializer helper callsites — 2026-11-15

A fresh private, read-only pass against the unchanged APK re-materialized the
same SHA-256 fingerprint and re-associated all 165 metadata image names with
the ARM64 codegen module records. The bounded registration pass counted
164,023 relocation-backed executable method-pointer slots. This is static
registration evidence, not proof that any path executes at runtime.

The bounded entry-window scan reproduced the previously documented direct
primitive-helper counts for LoginRequest and SessionRestoreRequest and added
the following LoginToBattleRequest observations:

| Entry method | Direct primitive helper | Call sites |
|---|---|---:|
| LoginToBattleRequest serializer | SimpleSerializer.serializeInt | 5 |
| LoginToBattleRequest serializer | SimpleSerializer.serializeString | 2 |
| LoginToBattleRequest deserializer | SimpleDeserializer.deserializeInt | 4 |
| LoginToBattleRequest deserializer | SimpleDeserializer.deserializeString | 2 |

The serializer and deserializer entry windows were 1,432 and 2,156 bytes,
respectively, bounded by the next distinct relocation-backed executable
entry in the same section and subject to the analyzer's 64 KiB maximum.

These are direct AArch64 `BL` callsite counts inside bounded entry windows.
They are **not** field counts, runtime execution counts, field order, or a
reconstructed LoginToBattleRequest schema. They do not identify which
property getter feeds each primitive helper, optionality, message IDs,
authentication semantics, handshake order, compression/encryption placement,
or APK/server compatibility. No raw addresses, instruction words, APK bytes,
packet captures, endpoints, or proprietary assets are included.


## Receiver zipped-message membership lookup — 2026-11-15

A fresh authorized, read-only pass was run against the unchanged APK fingerprint
at the top of this document. The private ARM64 ELF and metadata remained outside
the repository. A new .eh_frame_hdr index resolved the receiver's direct-call
lookup helper to an exact FDE initial-PC entry; its analysis window ends at the
next FDE start in the same executable section and is 480 bytes. The index
emits no addresses or instructions. This window is a bounded native-analysis
window, not a claim about runtime execution.

The second SimpleDeserializer.deserializeInt result in Receiver.Cycle is
passed as the integer key to that helper. Its body has the structural shape of
a HashSet-style membership lookup: it obtains a bucket array and count,
computes a bucket index, traverses 12-byte entries with hash/next/value
components, and invokes a comparer indirectly. This is materially different
from treating the call as an unresolved generic dictionary lookup.

The owner is now strongly attributed to NetworkSettings static state. The
same class-reference cell is used by Receiver.Cycle and NetworkSettings::.cctor.
The initializer stores a newly constructed collection into the first static
field slot; the metadata field inventory places m_zippetMessageTypes as the
first non-scalar collection field on NetworkSettings. Receiver.Cycle reads
that same static slot before a branch leading into later receive processing.
The best-supported interpretation is that the second integer is used as a
membership key in NetworkSettings.m_zippetMessageTypes, a set named for zipped
message types.

This resolves the static collection owner and narrows the integer's role, but
it does not establish a stable numeric wire-message-ID mapping. The branch's
runtime outcome, exact compression range/placement, encryption, complete
frame boundaries, sender/receiver symmetry, handshake order, LoginRequest
field order, and APK/server compatibility remain unverified. The four-byte
receive-length candidate remains a static candidate; the effective runtime
value and direct field-access relationship of NetworkSettings.HeaderLength
are still unresolved.

The earlier note that the second integer's static collection owner was
unresolved is superseded by this stronger static attribution. No packet bytes,
native addresses, raw instructions, APK/native assets, endpoints, or proprietary
resources were committed, and no official server was contacted.

The helper-boundary parser is documented in AARCH64_EH_FRAME_INDEX.md and is
covered by synthetic-only tests.


## CFG-scoped memory-access observations — tooling only

The native callsite report now includes `cfg_memory_access_observations` for
each selected method entry window. It decodes a bounded subset of integer
LDR/STR unsigned-scaled-immediate instructions and annotates each event with
its relative instruction index, basic-block index, access width, registers,
encoded displacement and structural reachability from the entry block.

The CFG builder recognizes a limited branch subset. Both outcomes of a
conditional branch are assumed; no flags or register predicates are evaluated.
Direct unconditional branches follow only an in-window target, while recognized
indirect branches and returns terminate the path. Unknown branch encodings and
external targets are not fully resolved. This is a bounded structural graph,
not a complete disassembler or execution trace.

The base register remains unresolved. An encoded displacement cannot be
identified as a managed field offset or attributed to a static field. The
summary does not establish object/static-field provenance, runtime values,
field identity, or whether a path executes. Only unsigned-immediate integer
load/store forms are included; SIMD/FP, sign-extending, unscaled,
pre/post-indexed, pair and atomic forms remain omitted.

Synthetic instruction-vector tests validate the decoder and graph bookkeeping
only. No new APK analysis or protocol finding is implied. In particular, this
does not link any access to `NetworkSettings.HeaderLength`; the receive-length
candidate, complete framing, compression placement, handshake and LoginRequest
field order remain unverified. The real APK adapter stays disabled pending a
provenance-reviewed authorized client-side fixture or local runtime trace.

## Bounded memory-base provenance tooling — 2026-11-17

The redacted callsite report now includes
`cfg_memory_base_provenance_observations` for each resolved
method window. This is a separate symbolic pass over supported unsigned-offset
integer LDR/STR instructions. It tracks ADRP, 64-bit ADD-immediate, unshifted
64-bit MOV copies, and 64-bit LDR results only when the effective slot matches
a caller-supplied relative-relocation entry. It reports symbolic provenance
classes and instruction-relative indexes, not absolute addresses or raw words.

The pass drops state at unknown instructions, calls, backedges and
multi-predecessor joins. Conditional edges assume both outcomes. It does not
model stack spills, arbitrary loads, IL2CPP static-field layout or runtime
values. A relocation-loaded pointer is not a managed-object or field identity.
Synthetic tests validate the analyzer only; the APK was not re-analyzed by
this tooling change. This does not identify NetworkSettings.HeaderLength or
establish framing. The authorized client-side fixture/runtime-trace blocker
remains unchanged.



## Fresh authorized APK re-verification — 2026-11-17

The unchanged authorized APK was read again from a private workspace. Its SHA-256 matched the established fingerprint at the top of this document. The archive contains 7,368 entries, no duplicate member names, and the full ZIP CRC test reported no bad member. The metadata is IL2CPP v31 with 31,187 type definitions, 197,631 method definitions and 165 metadata images. The fresh bounded codegen pass associated all 197,631 method slots with 161 non-empty native module pointer tables; 164,023 slots have AArch64 relative relocations to executable sections. The APK, native library, raw instructions, native addresses and packet bytes remain private.

### Receiver.Cycle receive path

A fresh private method-entry mapping and disassembly rechecked the bounded `Receiver.Cycle` window:

- The initial `ClientNetworkStreamBuffer.SetDataAvailable` call has a statically known second-argument register value of 4.
- The following `AbstractClientBuffer.Write` call has a statically known third-argument register value of 4.
- The next direct `SimpleDeserializer.deserializeInt` call is made with offset argument zero.
- Its result is compared with the `0x48545450` HTTP marker. On the non-marker branch, the same returned value flows into the later `SetDataAvailable` argument and `AbstractClientBuffer.Write` count argument.
- A second direct `deserializeInt` call remains associated with a static-state lookup before the decompression, `MessageMeta` construction and receiver-queue handoff path.

This strengthens the receive-side four-byte big-endian length-prefix **candidate** with fresh register-level static observations. It is still a bounded native entry-window analysis, not a runtime trace, complete frame contract, or proof that this branch executes for every connection.

### Sender and login limits

The bounded `Sender.Cycle` window again contains two `SimpleSerializer.serializeInt` callsites, one `ZipCompression` callsite and two `ClientStreamBuffer.Write` callsites. It also contains an `AbstractClientBuffer.Read` call with a statically known count argument of 4. These callsites do not prove sender/receiver framing symmetry or assign definitive semantics to either serialized integer.

The LoginRequest serializer/deserializer entry windows again contain direct helper-call counts of 19 integer, 16 string, 2 long and 1 boolean operations on the serializer side, versus 14 integer, 16 string, 2 long and 1 boolean operations on the deserializer side. These are not field counts or field order.

The new ADR decoder was added to the generic analyzer, but no ADR instruction was observed in the selected NetworkSettings, Receiver, Sender or LoginRequest entry windows in this pass; the observed address-building instructions there use ADRP. This negative observation does not change any protocol conclusion.

### Remaining limits

The relationship between the `NetworkSettings.HeaderLength` metadata field and the receive-side fixed four-byte setup remains unresolved. The effective runtime field value, complete outer frame, sender/receiver symmetry, compression/encryption placement, message IDs, handshake order, LoginRequest field order and unchanged-APK end-to-end behavior remain unverified. The APK-facing adapter remains disabled. No extracted endpoint was contacted.

## Independent private APK/native re-verification — 2026-11-19

The original `aow.apk` was re-materialized into a private workspace and read
successfully in this pass. Its SHA-256 again matched
`c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`.
The APK is 256,468,647 bytes; its ZIP has 7,368 entries, no duplicate member
names, and the full CRC test reports no bad member. The metadata member is
26,021,348 bytes and the ARM64 `libil2cpp.so` member is 166,150,720 bytes.
No APK or extracted member was added to the repository.

A fresh offline IL2CPP v31 / ELF64 AArch64 registration pass matched all
165 metadata images to native codegen modules. It rechecked 197,631 metadata
method definitions and pointer slots; 164,023 pointer slots have
AArch64-relative relocations to executable sections. The native type-pointer
registration scan found one unique table of 124,985 entries.

### Receiver and sender entry-window recheck

The fresh bounded `Receiver.Cycle` entry window contains two direct
`ClientNetworkStreamBuffer.SetDataAvailable` callsites, two
`AbstractClientBuffer.Write` callsites, two
`SimpleDeserializer.deserializeInt` callsites, one
`ClientArrayUtils.ZipDecompress` callsite and one `MessageMeta` constructor
callsite.

At the first read pair, the statically recovered count arguments are both 4:
the first `SetDataAvailable` receives 4 and the following
`AbstractClientBuffer.Write` receives 4. The first `deserializeInt` result
is compared with the HTTP marker. On the non-marker branch, that same result
is passed to the next `SetDataAvailable` and `AbstractClientBuffer.Write`
count arguments. This independently rechecks the receive-side four-byte
length-prefix **candidate** and the special HTTP-marker branch. It does not
prove runtime execution or a complete packet contract.

The second `deserializeInt` result is passed to a subsequent helper in the
bounded window; the owning type and semantic meaning of that helper remain
unresolved in this pass. No message-ID or dictionary interpretation is added.

The fresh bounded `Sender.Cycle` entry window contains two
`SimpleSerializer.serializeInt` callsites, one
`ClientArrayUtils.ZipCompression` callsite, one
`ClientNetworkStreamBuffer.SetDataAvailable` callsite and two
`ClientStreamBuffer.Write` callsites. These associations do not establish
which serialized integer is a frame length, the exact write ordering on an
executed path, or Sender/Receiver symmetry.

### Static NetworkSettings defaults rechecked

The v31 field/default tables again identify
`NetworkSettings.HeaderLength` with static default 4 and
`NetworkSettings.ZipIntermediateBufferSize` with static default 4096.
Both field type indexes resolve to IL2CPP `I4` through the unique native
type-pointer registration table. These are metadata defaults, not proof that
the runtime initializes or reads either field on the active connection path.

### Remaining limits

No authorized client-to-server runtime byte fixture or test-client trace was
available in this pass. The complete outer frame, sender/receiver symmetry,
compression placement, message IDs, handshake sequence, LoginRequest field
order and unchanged-APK end-to-end behavior remain unverified. The real AOW
adapter remains disabled and no official endpoint was contacted. Native
addresses, raw instructions, APK bytes and extracted assets remain private.


## Evidence reconciliation — 2026-11-19

The 2026-11-15 bounded FDE/helper-body pass above remains the strongest static
attribution for the Receiver membership collection: the helper has a
HashSet-style bucket traversal, and its static object provenance was
cross-referenced with `NetworkSettings::.cctor` and the metadata field
inventory to strongly attribute the collection to
`NetworkSettings.m_zippetMessageTypes`.

The independent 2026-11-19 bounded Receiver entry-window re-verification
again observed the second decoded integer flowing to a subsequent helper, but
did not independently resolve that helper's owner or semantic meaning in that
pass. This is a narrower recheck, not contrary evidence against the earlier
static cross-reference. Preserve the result as a **strong static attribution
only**, not runtime confirmation. The integer is not established as a stable
numeric wire message ID; runtime branch outcome, compression range/placement,
complete frame semantics, Sender/Receiver symmetry and APK compatibility
remain unverified.


## Conditional branch predicate and terminal-edge summaries — tooling only

The bounded AArch64 CFG report now records the encoded predicate for each
recognized conditional terminator:

- `B.cond`: condition-code number and its architectural mnemonic;
- `CBZ/CBNZ`: encoded register index, 32/64-bit width and zero/nonzero test;
- `TBZ/TBNZ`: encoded register index, tested bit index and zero/nonzero test.

Path summaries retain the predicate alongside the taken or fallthrough outcome.
A conditional instruction at the end of the bounded entry window also reports
a fallthrough exit when that edge leaves the window, even if its taken target
remains inside the window. This avoids silently omitting one possible edge.

These are decoded instruction operands, not evaluated predicates. The analyzer
does not recover NZCV flags, register values, path constraints, or the
runtime-selected edge. Register indexes are native instruction operands, not
managed field identities. The added summaries do not establish which branch
executes in the APK, packet framing, message semantics, handshake order,
LoginRequest field order, or client/server compatibility.


## Relative instruction locations for conditional path predicates — tooling only

Conditional branch-condition records now include the terminator's
instruction_index when the source CFG block carries a validated instruction
range. The index is relative to the bounded method entry window, so it can be
correlated with redacted callsite observations without publishing native
addresses. Legacy hand-authored CFG summaries without instruction ranges keep
their prior shape and do not receive a fabricated index.

This is location metadata only. It does not evaluate B.cond flags or CBZ/TBZ
register values, infer a runtime-selected edge, or establish packet framing,
message semantics, handshake/login order, or APK compatibility.


## CFG instruction-window integrity — 2026-11-20

Newly generated CFG summaries include `control_flow_instruction_count`, the
number of AArch64 instructions in the bounded method window. When this field is
present, the path summarizer requires every basic block to carry a valid
instruction range, rejects ranges outside the declared window, and verifies
that block ranges form a contiguous, non-overlapping partition of the window.
Legacy hand-authored summaries without the extent field remain supported.

Conditional successor-edge labels now require a matching decoded branch
predicate on a conditional terminator. This prevents malformed or partially
constructed summaries from being presented as predicate-backed branch paths.
These checks validate the internal consistency of static evidence only; they
do not evaluate predicates, select runtime edges, or establish wire semantics.


## CFG successor and external-exit contract validation — 2026-11-20

Path summarization now validates the edge/exit contract for generated CFG
summaries that declare a complete instruction-window extent. Conditional
terminators must carry a decoded predicate and account for each possible
outcome exactly once: either an internal taken/fallthrough edge or the
corresponding external-exit flag. An internal edge cannot coexist with the
same outcome being marked external.

Non-conditional terminators are restricted to their compatible edge kinds:
ordinary blocks may fall through, direct branches may have one branch target,
resolved indirect branches must have one in-window target, and returns or
unresolved indirect terminal branches cannot have successors. Exit flags must
be explicit booleans and remain false for non-conditional terminators.
The CFG truncation marker is also type-checked: complete-window summaries
must explicitly provide a boolean marker, and malformed values such as integers,
strings, or null are rejected rather than being treated as an untruncated CFG.
Legacy summaries without a declared instruction extent retain their previous
compatibility behavior when the marker is absent.

Synthetic tests cover valid two-way conditional paths, conflicting external
flags, missing predicates, incompatible return edges, invalid resolved
indirect-branch edges, and missing exit metadata. This is CFG consistency
validation only; it does not evaluate branch predicates, select runtime paths,
or establish AOW packet, handshake, login, or APK compatibility.


## Authorized APK native callsite recheck — 2026-11-20

The unchanged authorized APK was read in a private workspace and its SHA-256
matched the established fingerprint. Fresh bounded metadata/codegen mapping and
AArch64 disassembly were performed locally. No APK, metadata, native library,
raw address, instruction word, packet, capture, endpoint, or proprietary asset
was added to this repository.

The following observations are static callsite evidence only:

- `Receiver.Cycle` contains two direct calls to
  `SimpleDeserializer.deserializeInt`. The first returned value is compared
  with the four-byte `HTTP` marker. On the non-marker branch, the value is
  passed to `ClientNetworkStreamBuffer.SetDataAvailable`. This does not by
  itself establish a complete frame length or header contract.
- The second returned integer is passed as an argument to a native lookup
  helper that is not uniquely mapped to a metadata method in this pass. Its
  exact owner, key semantics, and runtime-selected meaning remain unresolved.
- `Sender.Cycle` contains two direct calls to
  `SimpleSerializer.serializeInt` and a direct
  `ClientArrayUtils.ZipCompression` callsite. `Receiver.Cycle` contains a
  direct `ClientArrayUtils.ZipDecompress` callsite. These paired method names
  do not prove compression placement, algorithm, framing symmetry, or payload
  boundaries.
- `NetworkSettings` static initialization stores 2,097,152 in the backing
  slot read and written by the `ReceiverUnzippedBufferMaxCapacity` accessors.
  This is a buffer-capacity setting, not a packet-size, header-length, or
  negotiated wire limit.

Still unverified: complete framing, sender/receiver symmetry, compression
placement and format, effective `HeaderLength` use, handshake sequence,
LoginRequest field order, and unchanged-APK login. No authorized
Client-to-Server runtime fixture or provenance-reviewed local runtime trace is
available. The real AOW adapter remains disabled; no official endpoint was
contacted.
