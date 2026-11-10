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
- `CheckSocket`, `Ping`

The metadata string heap contains `1336` unique identifiers ending in `STSerializer`, `1336` ending in `STDeserializer`, and `1336` matching base identifiers with both suffix forms. All ten message-related identifiers listed above have both suffix forms.

## What this proves — and what it does not

This is useful static evidence that the APK contains a substantial message serialization/deserialization layer and identifiers related to connection, login, and session restoration.

It is **not** a recovered wire protocol. The string heap alone does not provide:

- packet IDs or numeric message type mappings;
- field order, field types, optionality, or serialization algorithm;
- transport choice, framing, byte order, compression, or encryption;
- endpoint selection or a verified server address;
- application handshake sequence or authentication semantics;
- proof that any synthetic server accepts the unchanged APK.

The identifier strings are recorded as candidates, not promoted to verified wire facts. No endpoint values, IP addresses, raw packet captures, decompiled source, APK bytes, or proprietary assets are included. No remote host was contacted.

## Reproduction

Run the local analyzer against an authorized APK:

```bash
python tools/il2cpp_metadata_inventory.py /path/to/authorized/aow.apk --output /private/local/il2cpp_protocol_inventory.json
```

The analyzer supports the observed metadata version 31 only, checks archive/member bounds and header offsets, and emits only allowlisted identifier strings and aggregate counts. Its tests use synthetic ZIP/metadata fixtures and never include the original APK.
