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


## Primitive payload encoding — 2026-11-10

Private read-only inspection of the native `SimpleSerializer` and `SimpleDeserializer` method bodies provides strong static evidence for the primitive payload layer:

- `serializeChar` passes the high byte first and then the low byte to the underlying virtual writer; `deserializeChar`/`deserializeShort` read two bytes and combine the first as the high byte. This is a 16-bit big-endian code-unit/short representation.
- `serializeInt` serializes the high 16-bit half before the low half; `deserializeInt` reads two 16-bit halves in the same order. This supports big-endian 32-bit integers.
- `serializeLong` emits four 16-bit chunks from most-significant to least-significant; `deserializeLong` combines two 32-bit values high half first. This supports big-endian 64-bit integers.
- `serializeString` writes a 16-bit length, then each .NET string character as a 16-bit code unit. Null is written as `0xFFFF`; lengths at or above `0x8000` are rejected. `deserializeString` treats a length with the sign bit set as null and reads valid strings through the character-array path. This supports a UTF-16BE code-unit payload with a signed 16-bit length/sentinel.
- `serializeBoolean` masks the value to one bit before a single byte write; `deserializeBoolean` returns true only when the byte equals `1`. `serializeByte`/`deserializeByte` use the one-byte primitive path.

The server now has an isolated `server/aow_primitive_codec.py` implementation with synthetic known-vector tests. It is **not** wired into network handlers and must not be mistaken for a complete AOW packet codec. It does not implement the outer frame, header, message ID, compression/encryption, handshake, or LoginRequest field order.

The codec preserves UTF-16 surrogate code units and distinguishes null from empty strings. The deserializer mirrors the native sign-bit behavior for string lengths: any 16-bit length with bit 15 set returns null, while the serializer only emits the `0xFFFF` null sentinel and rejects lengths `>= 0x8000`.

No APK bytes, native addresses, raw instructions, endpoint values or packet captures are committed.


## Direct method-target resolution — 2026-11-10

The offline analyzer now resolves direct AArch64 B/BL destinations found inside the bounded Login/Registration/Session serializer entry windows against the metadata-backed method-pointer table. It emits only method labels and aggregate counts; native addresses and instructions remain private. Targets that do not map uniquely are counted as unresolved or ambiguous.

A second private offline pass over the unchanged APK reproduced these direct-call associations:

- LoginRequest serializer: 19 direct serializeInt, 16 serializeString, 2 serializeLong, 1 serializeBoolean, and 1 GearGamesRunTimeException constructor call.
- LoginRequest deserializer: 14 direct deserializeInt, 16 deserializeString, 2 deserializeLong, 1 deserializeBoolean, plus the LoginRequest constructor, diagnostic string conversion/concatenation and exception construction.
- LoginAnswer serializer: 15 direct serializeInt, 3 serializeString and 1 serializeByte.
- LoginAnswer deserializer: 10 direct deserializeInt, 3 deserializeString and 1 deserializeByte, plus its constructor and diagnostic/error paths.

The target-resolution pass also identifies direct method names outside the primitive helper allowlist. Indirect BLR calls remain unresolved by this static pass; they are not assigned guessed property names.

These results improve call-target attribution but **do not establish field order**. The windows are bounded by the next distinct relocation-backed executable entry, not formal function boundaries. Some instructions may be shared or belong to adjacent compiler-generated paths. The 79 indirect calls in the LoginRequest serializer and 74 in its deserializer remain unresolved. No packet framing, message ID, handshake order or APK/server compatibility is inferred.


## Receiver/Sender network callsite inventory — 2026-11-13

The offline analyzer now emits a redacted `network_callsite_summary` for selected
`Receiver.Cycle`, `Sender.Cycle`, `MessageDispatcher.Dispatch/TypeRegister`, and
`MessageHelper.InternalGetMessageType/GetMessageType` entry windows. It reports
metadata-backed direct method targets, allowlisted primitive-helper callsites,
and relocation-backed indirect-call resolutions where unique. Native addresses,
raw instructions, relocation addends, packet bytes and endpoints are not emitted.

A fresh read-only disassembly of the unchanged authorized APK confirms these
callsite observations:

- `Receiver.Cycle` has two direct `SimpleDeserializer.deserializeInt` callsites.
  The first result is compared with the static `0x48545450` HTTP marker; the
  non-marker path reuses it as the subsequent stream read count. The later
  integer is passed as a key argument to an internal hash-bucket lookup. Its
  dictionary owner and semantic label remain unresolved; do not call it a wire
  message ID or sequence number without further evidence.
- `Sender.Cycle` has two direct `SimpleSerializer.serializeInt` callsites, a
  `ClientArrayUtils.ZipCompression` callsite, and two
  `ClientStreamBuffer.Write` callsites. This is not enough to establish that
  Sender emits the same framing candidate used by the Receiver branch.
- `MessageDispatcher.Dispatch` contains a direct path to global/unhandled
  message-handler methods and uses a type-keyed listener lookup. This describes
  client-side dispatch structure, not a recovered wire ID mapping.

The bounded entry windows end at the next distinct relocation-backed executable
entry in the same section; they are not formal function boundaries. These
summaries are static callsite evidence only. They do not establish active
runtime paths, exact field order, frame boundaries, compression/encryption
placement, handshake/login semantics, or APK/server compatibility. The APK,
native binaries, raw disassembly and proprietary assets remain outside this
public repository.


## Network field metadata summary — 2026-11-13

The allowlisted analyzer emits a redacted `network_field_summary` for
selected transport fields. In addition to namespace, type, field name,
metadata token and default-record presence, it now reports the opaque 32-bit
`field_type_index` stored in the allowlisted metadata field definition. This
index is not resolved to a managed type name and is not a runtime field value.
The report still excludes default-value bytes, field offsets, native
addresses and instructions.

The fresh offline pass found:

- `NetworkSettings.HeaderLength` has a metadata field-default record. The
  default value itself is not decoded by this summary; the type index is
  retained only as a follow-up metadata-resolution key.
- `MessageHelper` declares both
  `m_messageTypeByMessageClass` and
  `m_messageClassByMessageType`, documenting the two dictionary directions
  without publishing runtime contents. Their type indices are retained as
  opaque metadata references, not interpreted as dictionary contents.

This metadata summary complements the native callsite trace. It does not by
itself resolve the field's managed type, prove the effective `HeaderLength`,
identify the exact static field load/store, recover numeric message IDs, or
establish a packet schema.
