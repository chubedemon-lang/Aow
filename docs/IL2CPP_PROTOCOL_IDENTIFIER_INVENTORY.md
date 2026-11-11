# AOW IL2CPP protocol identifier inventory

**Date:** 2026-11-10  
**Method:** authorized, offline, read-only inspection of the supplied `aow.apk`  
**Compatibility status:** not established

## Artifact fingerprint

- APK size: `256468647` bytes.
- APK SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`.
- ZIP entries: `7368`; a full archive CRC pass returned no failing entry.
- Metadata member: `assets/bin/Data/Managed/Metadata/global-metadata.dat`.
- Metadata member size: `26021348` bytes.
- Header magic: `0xfab11baf`.
- Metadata version: `31`.
- String heap: offset `0x128444`, size `0x331dec` (`3349996` bytes).

## Observations from the metadata string heap

The following namespace tokens were present:

- `com.geargames.aow.messages`
- `com.geargames.common.network`
- `com.geargames.unity.network`
- `com.geargames.aow.config`

Network-related identifier strings observed:

- `NetworkSocket`, `NetworkSocketStream`, `NetworkSettings`
- `MessageDispatcher`, `MessageHelper`, `MessageMeta`, `MessageTypes`
- `IClientMessageSerializer`, `IClientMessageDeserializer`
- `RemoteServerAddresses`, `ServerAddressHelper`
- `ClientServerAddressConfiguration`, `ClientServerPreset`, `TransportType`
- `CSEstablishConnection`, `CSHttpSendRequestAndReceiveResponse`

Message-related identifier strings observed:

- `LoginRequest`, `LoginAnswer`
- `SessionRestoreRequest`, `SessionRestoreAnswer`
- `LoginToBattleRequest`, `LoginToBattleAnswer`
- `RegistrationRequest`, `RegistrationAnswer`
- `BattleSessionRestoreRequest`, `BattleSessionRestoreAnswer`
- `CheckSocket`, `Ping`

The metadata string heap contains `1336` unique identifiers ending in `STSerializer`, `1336` ending in `STDeserializer`, and `1336` matching base identifiers with both suffix forms. The listed login/session/connection identifiers have matching suffix strings.

## Type, field, and method table associations

The type inventory validates and reads the version-31 type, field, and method definition tables. The observed APK contains:

| Table | Records |
|---|---:|
| Type definitions | 31,187 |
| Method definitions | 197,631 |
| Field definitions | 119,710 |

The record strides used are version-specific: `Il2CppTypeDefinition` 88 bytes, `Il2CppMethodDefinition` 36 bytes in metadata v31, and `Il2CppFieldDefinition` 12 bytes. The implementation checks each section's bounds, record alignment, target type field/method ranges, and each target method's declaring-type index before reporting names.

### Login and session types

- `com.geargames.aow.messages.LoginRequest`: 31 metadata fields and 65 methods. Field names include `version`, `buildNumber`, `protocolVersion`, `serializationVersion`, `logicVersion`, `deviceUniqueIdentifier`, `token`, `gameSessionId`, `clientTags`, and `deviceToken`.
- `com.geargames.aow.messages.LoginAnswer`: 21 metadata fields and 18 methods. Non-status field names include `sessionId`, `zipped`, `analyticsDataInt`, `errorDescription`, `maxClientBufferSize`, and feature-toggle fields.
- `com.geargames.aow.messages.RegistrationRequest`: 27 metadata fields and 49 methods; includes version/build/protocol, device and platform identifiers, `gameSessionId`, `restoreMode`, and `deviceToken` names.
- `com.geargames.aow.messages.RegistrationAnswer`: 14 metadata fields and 8 methods; includes `token` and `errorDescription` plus status identifiers.
- `com.geargames.aow.messages.SessionRestoreRequest`: 3 metadata fields: `reason`, `sessionId`, `gameSessionId`.
- `com.geargames.aow.messages.SessionRestoreAnswer`: 12 status identifier fields and 5 methods.
- Matching serializer/deserializer type definitions are present for the login and session message identifiers; their method names include `serialize` and `deserialize`.

### Message type registry candidates

`com.geargames.aow.messages.MessageTypes` is a type definition with 761 fields. The metadata field-name table includes identifiers such as:

- `LOGIN_REQUEST`, `LOGIN_ANSWER`, `REGISTRATION_REQUEST`, `REGISTRATION_ANSWER`
- `SESSION_RESTORE_REQUEST`, `SESSION_RESTORE_ANSWER`
- `LOGIN_TO_BATTLE_REQUEST`, `LOGIN_TO_BATTLE_ANSWER`
- `BATTLE_SESSION_RESTORE_REQUEST`, `BATTLE_SESSION_RESTORE_ANSWER`
- `PING`, `CHECK_SOCKET`
- `BATTLE_LOAD_PROGRESS_REQUEST`, `BATTLE_LOAD_PROGRESS_ANSWER`
- `START_BATTLE_NOTIFICATION`, `BATTLE_FINISH_NOTIFICATION`
- `SHOP_BOX_REQUEST`, `SHOP_BOX_ANSWER`
- `JOIN_PVE_MISSION_REQUEST`, `JOIN_PVE_MISSION_ANSWER`
- `LOBBY_CREATE_REQUEST`, `LOBBY_CREATE_ANSWER`
- `MAP_BUNDLE_CI_REQUEST`, `MAP_BUNDLE_CI_ANSWER`
- `BATTLE_AI_COMMAND_UNITS_MOVE`

These are field names only. Numeric constants are deliberately not reported: the field-default data type/width and encoding have not been independently resolved.

### Network and framing leads

- `com.geargames.common.network.Network`: 26 fields and 58 methods. Metadata names include `m_tcpClient`, `m_socket`, `m_sender`, `m_receiver`, `m_messageDispatcher`, `m_serializationManager`, and `m_tcpNoDelayEnabled`. Method identifiers include `ConnectBeginAsync`, `SetCryptoProvider`, `SetTcpNoDelayFlag`, `ApplyTcpNoDelayFlag`, `SendMessage`, `SendMessageUnreliable`, `SessionRestored`, and `SessionBroken`.
- `com.geargames.common.network.NetworkSettings`: 28 fields and 16 methods. Field names include `HeaderLength`, `ZipIntermediateBufferSize`, socket receive/send buffer sizes, encrypted/decrypted/zipped/unzipped buffer capacities, read/write timeout fields, `HeartbeatTimeout`, `m_zippetMessageTypes`, and `m_notSessionedMessageTypes`.

  The `HeaderLength` field also has a field-default metadata record. The public inventory reports record presence only; its default type/value is not decoded here, and this does not prove a runtime read or establish that the value equals the receive-side four-byte immediate.
- `Sender` and `Receiver` definitions contain stream/header/encrypted/decrypted/zipped/unzipped buffer identifiers. `Sender` has `TrySendHeartbeat`; `Receiver` has `DoStreamReadedBytes` and `ReadStreamBufferToEnd`.
- `MessageHelper` has fields named `m_messageTypeByMessageClass` and `m_messageClassByMessageType`, plus methods `GetMessageType`, `GetMessageTypeName`, and `GetMessageClassName`.
- `MessageDispatcher` has `m_lastProcessedServerSequenceNumber` and a `Dispatch` method.
- `IClientMessageSerializer` declares `SerializeMessage`; `IClientMessageDeserializer` declares `DeserializeMessage`.
- `com.geargames.serialization.MessageMeta` has start/end receiving timestamp properties.
- Main/battle session restore connector type definitions are present under `com.geargames.unity.network`.

These names provide concrete places to investigate the client implementation. They do **not** prove which code path is active in a particular build or session.

## What this proves — and what it does not

The metadata establishes type/field/method name associations for a client message layer, login/session message models, a message-type registry, and network sender/receiver abstractions. It also identifies a `HeaderLength` field and buffer names, which are useful framing leads.

It is **not** a recovered wire protocol. The metadata tables alone do not provide:

- numeric message IDs or a verified encoding of `MessageTypes` constants;
- field types, optionality, serializer field order, or payload encoding;
- exact header bytes/length, framing rules, byte order, compression or encryption algorithms;
- verified active transport, endpoint selection, or server address;
- application handshake order or authentication semantics;
- proof that any synthetic server accepts the unchanged APK.

The identifier names are not method bodies. The metadata field order is not assumed to be wire serialization order. No endpoint values, IP addresses, raw packet captures, decompiled source, APK bytes, or proprietary assets are included. No remote host was contacted.

## Reproduction

Run the two local analyzers against an authorized APK:

```bash
python tools/il2cpp_metadata_inventory.py /path/to/authorized/aow.apk --output /private/local/il2cpp_strings.json
python tools/il2cpp_type_inventory.py /path/to/authorized/aow.apk --output /private/local/il2cpp_types.json
```

The tools support the observed metadata version 31 only, check header/table bounds and record alignment, and emit allowlisted identifiers. Their tests use synthetic ZIP/metadata fixtures and never include the original APK.

## Format references

- [Perfare/Il2CppDumper `MetadataClass.cs` at the pinned source commit](https://github.com/Perfare/Il2CppDumper/blob/4741d46ba9cd6159c5d853eb9d6fc48b4bfa2b1a/Il2CppDumper/Il2Cpp/MetadataClass.cs) — version gates and field layouts for type, method, and field definitions.
- [Il2CppTypeDefinition v27–v31 layout](https://reverseengineering.wiki/index.php/Fact:IL2CPP_global-metadata.dat/struct/Il2CppTypeDefinition_v27_to_v31).
- [Il2CppMethodDefinition layout](https://reverseengineering.wiki/index.php/Fact:IL2CPP_global-metadata.dat/struct/Il2CppMethodDefinition).


## Raw signature-index follow-up

The read-only v31 inventory now records, for allowlisted message and network types:

- each field's raw metadata `type_index` and metadata token;
- each method's raw return-type index, return-parameter token, generic-container index, metadata token, flags, interface flags, slot and parameter list;
- each parameter's metadata name, raw type index and metadata token.

These values are copied from the v31 metadata records after table-bound and owner/range checks. **They are not resolved managed types.** The type indexes refer to the native IL2CPP type-registration layer and cannot be converted into names from the metadata tables alone. The metadata tokens are managed metadata identifiers, not AOW wire message IDs. The raw indexes do not reveal serializer field order or prove the runtime path is active.

The public tool emits only the targeted message/network type records and the existing allowlisted `MessageTypes` field names. Original APK bytes, native library bytes, extracted assets, and full local analysis output remain private.


## Field-default metadata linkage

The v31 inventory also exposes the raw field-default table association for each allowlisted field: the default-value type index and byte offset into the metadata default-data blob. These are metadata references only; the public inventory does not decode or publish constant values. The default-data byte offset is validated against the bounded data section, and duplicate/out-of-range field-default records are rejected.

A separate authorized local analysis resolved the inspected arm64 IL2CPP native type-registration table and found the `MessageTypes` field and default-value type references both use IL2CPP type code `I4`. This establishes their metadata storage type as 32-bit integer, not their on-wire encoding or runtime use. Numeric constants are intentionally kept out of this public repository; they remain candidates until the active message-dispatch/serialization path is independently confirmed.
