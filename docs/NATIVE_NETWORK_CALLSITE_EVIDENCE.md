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
  --output /private/local/network-callsite-evidence.json
```

The command is offline and emits method labels, bounded entry-window sizes and
aggregate call counts only. It does not emit APK bytes, native addresses, raw
instructions, packet bytes or endpoint values.

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
