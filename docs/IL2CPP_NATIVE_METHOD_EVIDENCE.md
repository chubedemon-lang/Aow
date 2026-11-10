# Native method entry-point evidence (offline)

**Date:** 2026-11-10  
**Input:** user-provided AOW APK, inspected read-only in a private workspace  
**Compatibility status:** not established

## Reproduction

Run the allowlisted analyzer locally:

```bash
python tools/il2cpp_native_method_evidence.py /private/path/aow.apk \
  --output /private/path/network-method-evidence.json
```

The tool reads only the IL2CPP v31 metadata member and arm64 `libil2cpp.so`
from the APK. It reuses the bounded metadata/ELF parser in
`tools/il2cpp_codegen_inventory.py`. It emits method names, parameter counts,
image names and relocation status only. It does not emit native addresses,
relocation addends, raw instructions, endpoints, packet bytes or assets.

## Result for the inspected APK

- APK size: 256,468,647 bytes.
- SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`.
- IL2CPP metadata version: 31.
- Metadata method definitions: 197,631.
- Allowlisted network methods observed: 20; 19 have relative-relocation-backed pointers into executable sections.
- The login/session serializer allowlist covers 20 methods across LoginRequest/Answer, RegistrationRequest/Answer, SessionRestoreRequest/Answer, LoginToBattleRequest/Answer, and BattleSessionRestoreRequest/Answer. A private offline pass mapped all 20 to relative-relocation-backed executable entries in `ConvertedAssembly.dll`.
- The combined analyzer therefore reports 40 allowlisted methods total and 39 executable entry points (the remaining network overload has no relative relocation at its slot).
- One `MessageHelper.GetMessageType` overload (zero parameters) has no
  `R_AARCH64_RELATIVE` entry at its codegen slot. This does not prove that the
  overload has no implementation; it may use shared, null, or another
  registration path.

The 19 network executable-entry records are in the ELF `.il2cpp` section and cover:

- `NetworkSocketStream.Read/Write`;
- `Network.ConnectBeginAsync`, `SendMessage` and received-message processing;
- `NetworkSettings` static initializer and constructor;
- `Receiver` cycle, stream callback and buffer/HTTP helper methods;
- `Sender` cycle, heartbeat and serialization test methods;
- `MessageDispatcher.Dispatch/TypeRegister`;
- `MessageHelper.InternalGetMessageType` and one `GetMessageType` overload.

## Static disassembly observations

A private, read-only spot-check of the resolved native entries shows:

- `NetworkSocketStream.Read` and `Write` dispatch to the wrapped stream object.
- `Network.SendMessage` follows message-metadata and serializer-related
  indirect-dispatch paths.
- `Network.ProcessingOneReceivedMessage` invokes `MessageDispatcher.Dispatch`.
- `Receiver.Cycle` calls the receiver's HTTP-response and stream-buffer helper
  methods in addition to its stream-processing path.

These are method-body observations from this build, not proof that a particular
path is active in every session. The current analysis has **not** established
how `NetworkSettings.HeaderLength` is consumed, the exact frame layout,
byte order, compression/encryption activation, message IDs on the wire,
serializer field order, handshake sequence or login semantics.

## Interpretation and limits

This is stronger than a metadata-name inventory: it associates selected
metadata methods with relocation-backed executable native entry points. It is
still not a recovered wire protocol. A method pointer alone does not establish
the method's full semantics, runtime reachability, or client/server compatibility.

No packet fixtures were fabricated. No endpoint was contacted and no official
server infrastructure was accessed. The APK, native binaries, detailed local
disassembly and proprietary assets remain outside this public repository.

## Next evidence required

Continue tracing the native read/write call path and the actual use of
`HeaderLength`, then follow the login serializer/deserializer. A real protocol
adapter remains blocked until an authorized test-client log or redacted packet
fixture can reproduce the byte stream. Keep synthetic framing explicitly
separate from the AOW wire contract.


## Login/session serializer entry-point coverage — 2026-11-10

The allowlisted native-method analyzer now also maps paired serializer/deserializer entry points in `com.geargames.serialization.serializers` for:

- LoginRequest and LoginAnswer;
- RegistrationRequest and RegistrationAnswer;
- SessionRestoreRequest and SessionRestoreAnswer;
- LoginToBattleRequest and LoginToBattleAnswer;
- BattleSessionRestoreRequest and BattleSessionRestoreAnswer.

The authorized offline pass found 20 corresponding methods in `ConvertedAssembly.dll`, each with a relocation-backed pointer into executable code. The analyzer reports network methods and login/session serializer methods as separate categories and does not emit addresses or instructions.

This closes a tooling coverage gap: the prior analyzer allowlist mapped network sender/receiver and dispatcher methods but did not include these serializer/deserializer types. It does **not** recover serializer field order, field types, optionality, message IDs, payload encoding, framing, handshake order, or login semantics. Those remain unknown until native method-body tracing and an authorized redacted wire fixture reproduce them.


## LoginRequest primitive-helper callsites — 2026-11-10

A private offline disassembly spot-check of the unchanged APK's `LoginRequestSTSerializer.serialize` and `LoginRequestSTDeserializer.deserialize` entry windows found direct calls to the generic primitive helpers:

| Entry method | Direct helper | Call sites |
|---|---|---:|
| LoginRequest serializer | SimpleSerializer.serializeInt | 19 |
| LoginRequest serializer | SimpleSerializer.serializeString | 16 |
| LoginRequest serializer | SimpleSerializer.serializeLong | 2 |
| LoginRequest serializer | SimpleSerializer.serializeBoolean | 1 |
| LoginRequest deserializer | SimpleDeserializer.deserializeInt | 14 |
| LoginRequest deserializer | SimpleDeserializer.deserializeString | 16 |
| LoginRequest deserializer | SimpleDeserializer.deserializeLong | 2 |
| LoginRequest deserializer | SimpleDeserializer.deserializeBoolean | 1 |

The analyzer now summarizes these direct AArch64 `BL` callsites by helper name, and separately counts indirect `BLR` calls and direct calls outside the helper allowlist. The scan window is bounded by the next distinct relocation-backed executable entry in the same ELF section and is explicitly an entry window, not a formally recovered function boundary.

These are callsite counts, **not** field counts. They do not establish which property getter feeds each helper, the field order, optionality, wire IDs, byte encoding, framing, handshake sequence, or login semantics. No raw instructions, native addresses, APK bytes, or packet data are emitted or committed.
