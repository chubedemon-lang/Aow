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
