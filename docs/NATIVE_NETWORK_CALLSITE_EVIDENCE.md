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
calls are resolved only for the narrow relocation-backed ADRP/ADD/LDR/BLR-or-BR
pattern and a unique metadata method target; all other indirect calls remain
unresolved.

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

The scan supports only MOVZ/MOVN/MOVK and ADD-immediate register updates. Any
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
