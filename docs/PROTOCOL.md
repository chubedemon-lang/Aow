# AOW protocol evidence ledger

**Current status: unknown.** Unity IL2CPP and Addressables are present. Offline metadata now identifies a client message serializer/deserializer layer and socket sender/receiver abstractions, but no verified wire transport, packet framing, server host, authentication flow, or wire captures are available here.

| Component | Verified evidence | Status |
|---|---|---|
| Endpoint discovery | Address configuration type names only; no values published | Unknown |
| Transport | Socket/TCP-related metadata identifiers | Active transport unverified |
| Framing | `HeaderLength`, header/stream buffers, zipped/encrypted/decrypted buffer identifiers | Layout and rules unknown |
| Handshake | Login/registration/session type names | Application handshake sequence unknown |
| Serialization | Message type registry and paired serializer/deserializer type definitions | Wire encoding and field order unknown |
| Compression/encryption | Zipped/encrypted/decrypted buffer and crypto-provider identifiers | Algorithms and activation rules unknown |
| Login/session | Login, registration, and session-restore fields/methods identified | Wire semantics unknown |
| Player initialization | Not established | Unknown |
| World synchronization | Battle, lobby, map, and movement message names identified | Wire semantics unknown |

Add each discovery with APK version/hash, observation method, confidence, redacted evidence and a reproducible local test. Never publish tokens or other users' data.

## Offline candidate scanner safety and limits

Run `python -m tools.protocol_candidates /path/to/authorized.apk --output /private/local/report.json` on a locally held, authorized APK. This command reads the APK ZIP offline and makes **no network requests**. Reports must stay local and be reviewed before sharing.

The scanner intentionally emits only normalized URL **origins** (scheme, hostname and optional port) or host strings; it discards URL paths, queries, fragments, and userinfo, and suppresses strings containing credential-related keywords. This reduces accidental disclosure of embedded tokens, user identifiers and private paths. It is not a proof of safe publication: a hostname itself can still be sensitive, and a third-party analytics SDK can produce false positives.

The candidate output **cannot** establish which endpoint is used for gameplay, whether a hostname is active, or whether any particular transport or packet layout is supported. Never attempt to contact extracted hosts as part of this tool. Keep raw reports and APK bytes out of the public repository.

Before implementing an actual adapter, require independently verified and authorized evidence of client-facing transport/framing/handshake and a synthetic redacted test fixture with explicit provenance.

## Static IL2CPP metadata identifiers — 2026-11-10

An authorized, read-only offline pass inspected the user-provided APK without modifying it or extracting game assets.

- APK size: `256468647` bytes.
- APK SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`.
- ZIP entries: `7368`; a full `ZipFile.testzip()` pass reported no CRC failure.
- IL2CPP metadata member: `assets/bin/Data/Managed/Metadata/global-metadata.dat`, `26021348` bytes.
- Metadata magic: `0xfab11baf`; metadata version: `31`.
- Metadata string heap: offset `0x128444`, size `0x331dec` (`3349996` bytes).
- The heap contains `1336` unique `*STSerializer` identifier strings and `1336` unique `*STDeserializer` identifier strings; `1336` base identifiers have both suffix forms.

Observed namespace tokens include `com.geargames.aow.messages`, `com.geargames.common.network`, `com.geargames.unity.network`, and `com.geargames.aow.config`.

Observed network-related identifier strings include `NetworkSocket`, `NetworkSocketStream`, `NetworkSettings`, `MessageDispatcher`, `MessageHelper`, `MessageMeta`, `MessageTypes`, `IClientMessageSerializer`, `IClientMessageDeserializer`, `RemoteServerAddresses`, `ServerAddressHelper`, `ClientServerAddressConfiguration`, `ClientServerPreset`, `TransportType`, `CSEstablishConnection`, and `CSHttpSendRequestAndReceiveResponse`.

Observed message-related identifier strings include `LoginRequest`, `LoginAnswer`, `SessionRestoreRequest`, `SessionRestoreAnswer`, `LoginToBattleRequest`, `LoginToBattleAnswer`, `RegistrationRequest`, `RegistrationAnswer`, `BattleSessionRestoreRequest`, `BattleSessionRestoreAnswer`, `CheckSocket`, and `Ping`. Each has matching serializer/deserializer identifier suffix strings.

**Interpretation limit:** these are static metadata strings and table associations, not recovered method bodies or a wire specification. They do not establish message IDs, field layouts, payload encoding, framing, byte order, transport choice, endpoint selection, application handshake order, authentication semantics, or compatibility with the APK. In particular, names such as `NetworkSocket` and `TransportType` do not prove a specific active protocol. No extracted host/IP values are published and no remote host was contacted.

See [the detailed offline type/field/method inventory](IL2CPP_PROTOCOL_IDENTIFIER_INVENTORY.md) for table counts, login/session field names, and framing-related identifiers. Keep APK bytes and local reports outside this public repository.


## Raw IL2CPP signature indexes — 2026-11-10

The offline type inventory now preserves raw field, method-return, and parameter type indexes plus metadata tokens from the version-31 tables. This narrows the next investigation to the native type-registration data in `libil2cpp.so`, but does not resolve those indexes into managed type names. Metadata tokens are not wire message IDs. No field order, payload layout, framing rule, or active transport is inferred from these values.


## MessageTypes default metadata — 2026-11-10

The v31 metadata contains field-default records for the `MessageTypes` definition. In a private offline pass, the matching arm64 native type-registration array resolved the field and default-value type references to IL2CPP type code `I4` (32-bit integer). This identifies the static metadata storage type only. It does not prove that these constants are used as wire message IDs or establish their byte order/framing in transmitted packets. Numeric candidates remain private and are not committed.

## MessageTypes default-value aggregate cross-check — 2026-11-10

A further private offline pass over the same APK fingerprint found 761/761 MessageTypes field definitions have corresponding field-default records. The authorized arm64 native type-registration mapping used for this pass resolves both the field type and default-value type references to IL2CPP I4 (32-bit integer). Reading the bounded default-data records as 32-bit values yields 761 distinct raw bit patterns. The exact numeric candidates remain private and are not included in this public repository.

This is a stronger static metadata observation, but it still does **not** prove that these values are active wire message IDs, nor does it establish message-header byte order, serialization, framing, or dispatch behavior. The NetworkSettings metadata also has default records for HeaderLength and several buffer-capacity fields; their raw patterns are not treated as effective runtime lengths until the native initialization/read path is traced.

Next investigation target: the native execution path that populates MessageHelper's class/type dictionaries, the NetworkSettings initializer and the serializer/deserializer dispatch. No extracted endpoint was contacted.

## Native dispatch and codec signature leads — 2026-11-10

The version-31 method table provides additional name/parameter associations for the next native-code trace:

- MessageHelper declares InternalGetMessageType(type) and GetMessageType overloads; its reverse lookup helpers are GetMessageTypeName and GetMessageClassName.
- MessageDispatcher declares TypeRegister(type, listener), Register(type, listener), Dispatch(message), and global/unhandled message handler registration methods.
- Sender's constructor parameter names include socket, receiverMessageQueue, senderMessageQueue and messageSerializer. It also declares SetCryptoProvider and TrySendHeartbeat.
- Receiver's constructor parameter names include socket, receiverMessageQueue, senderMessageQueue and messageDeserializer. It declares SetCryptoProvider, DoStreamReadedBytes, GetHttpMessageResponse(header, streamBuffer), and ReadStreamBufferToEnd(streamBuffer).
- LoginRequestSTSerializer declares serialize(messageObject, buffer, context, logger); LoginRequestSTDeserializer declares deserialize(buffer, context, logger).

These are metadata method names and parameter-name associations only. They do not expose method bodies, prove invocation order, identify active transport, or define the bytes written to the socket. The next step is to map these metadata methods to native method pointers and inspect the code paths without publishing proprietary binaries or private captures.
