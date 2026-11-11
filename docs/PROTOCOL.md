# AOW protocol evidence ledger

**Current status: unknown.** Unity IL2CPP and Addressables are present. Offline metadata and native inspection identify a client message serializer/deserializer layer, primitive payload operations, and socket sender/receiver abstractions. No verified outer frame, active wire transport, server host, authentication flow, or client packet capture is available here.

| Component | Verified evidence | Status |
|---|---|---|
| Endpoint discovery | Address configuration type names only; no values published | Unknown |
| Transport | Socket/TCP-related metadata identifiers | Active transport unverified |
| Framing | `HeaderLength` metadata field and header/stream buffers; Receiver.Cycle has a fixed four-byte read followed by an integer-driven second read, with an HTTP-marker branch; Sender.Cycle has integer serialization and stream-write callsites | Four-byte big-endian length-prefix candidate only; `HeaderLength` value/use and runtime path are unverified |
| Primitive serialization | Native helper bodies indicate big-endian 16/32/64-bit values, UTF-16 code-unit strings and one-byte boolean/byte operations; isolated codec and synthetic vectors exist | Primitive payload layer only |
| Message schema | Message type registry and paired serializer/deserializer type definitions | Field order, optionality and wire IDs unknown |
| Handshake | Login/registration/session type names | Application handshake sequence unknown |
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

## Native method-pointer mapping — 2026-11-10

The offline codegen inventory tool now matches metadata image names to native codegen module records in the authorized arm64 IL2CPP library:

- 165/165 metadata images match native codegen modules.
- The 197,631 metadata method definitions match 197,631 native method-pointer slots.
- 164,023 slots have AArch64 relative relocations to executable sections.
- Relevant module counts: ScriptsAssembly.dll 56,481; ConvertedAssembly.dll 25,442; NetworkBase.dll 18; ResourceDispatcher.dll 2,970.

A private local mapping associates native pointer-table slots with the previously identified methods in MessageHelper, MessageDispatcher, NetworkSettings, Receiver, Sender, and the LoginRequest serializer/deserializer. Raw native addresses and detailed disassembly remain private. Some pointer slots have no relative relocation; they may be null, shared, or represented by another registration path, so the count is not a count of unique method bodies.

This supersedes the earlier “next step” statement that native method-pointer mapping was still pending. The mapping is now established statically, but method-body semantics and invocation order are not yet fully recovered.

### Protocol conclusions remain unchanged

- MessageTypes fields/defaults are stored as IL2CPP I4 values, but their active use as wire message IDs is not yet proven.
- The NetworkSettings header/buffer metadata and Receiver stream-buffer methods are identified, but the effective header length, header fields, framing, compression/encryption order and message field serialization order remain unknown.
- TCP/socket-related identifiers and a stream abstraction are present, but the active transport path and endpoint selection are not yet proven.
- LoginRequest and SessionRestore serializer/deserializer native entry points are mapped, but no complete request/response byte sequence or handshake order has been reproduced.

## Primitive payload encoding — 2026-11-10

Private read-only inspection of the native `SimpleSerializer` and `SimpleDeserializer` method bodies provides static evidence for primitive payload operations:

- `serializeChar` writes the high byte before the low byte; `deserializeChar`/`deserializeShort` combine two bytes high-first.
- `serializeInt` emits the high 16-bit half before the low half; `deserializeInt` reconstructs the value in the same order.
- `serializeLong` emits four 16-bit chunks from most-significant to least-significant; `deserializeLong` combines two 32-bit halves high-first.
- `serializeString` writes a 16-bit UTF-16 code-unit count followed by code units. Null is emitted as `0xFFFF`; lengths `>= 0x8000` are rejected. The deserializer treats any length with bit 15 set as null.
- `serializeBoolean` writes the low bit as one byte; `deserializeBoolean` is true only when the byte equals `1`. Byte operations use a one-byte path.

The isolated `server/aow_primitive_codec.py` implementation has synthetic known-vector tests and is intentionally not connected to network handlers. These findings describe primitive payload helpers only. They do not establish LoginRequest field order, optionality, outer framing/header, message IDs, compression/encryption, active transport, handshake sequence or APK compatibility.

No APK bytes, native addresses, raw instructions, endpoint values or packet captures are committed.


## Synthetic credential authentication boundary — 2026-11-10

The repository now contains a local-only PBKDF2-HMAC-SHA256 credential verifier that can issue a durable synthetic session after rechecking the credential in the same SQLite write transaction. This is a server-domain security primitive, **not** evidence of the APK's password encoding, hash/challenge algorithm, login message fields, handshake, or token format. It is not exposed as an HTTP route and must not be connected to an APK adapter until those client-facing semantics are established from authorized offline evidence and a redacted reproducible fixture.


## Conservative relocation-backed indirect-call analysis — 2026-11-11

The offline native-method analyzer now has an additional **tool capability** for a narrow AArch64 pattern: a contiguous ADRP, optional 64-bit ADD immediate, 64-bit unsigned-offset LDR, then BLR or BR. The loaded pointer is accepted only when the corresponding ELF relocation is R_AARCH64_RELATIVE, and the target must also match a unique metadata-backed executable method entry before a method label is reported.

The scanner clears its tracked register state on any unrecognized instruction (except NOP). Missing/non-relative relocations, ambiguous metadata targets, ordinary virtual calls and runtime-computed pointers remain unresolved. Output contains method labels and aggregate counts only; no native addresses or instruction words are emitted.

This change adds synthetic instruction/relocation tests only. **No new APK analysis was run for this change**, so existing unresolved indirect-call counts (including the previously recorded LoginRequest serializer/deserializer counts) are unchanged until the tool is run successfully against the exact authorized APK fingerprint. This narrow resolver is not a general AArch64 decompiler and does not establish field order, framing, message IDs, handshake, or APK compatibility.


## Framing candidate update — 2026-11-11

A read-only disassembly pass over the exact APK fingerprint recorded in docs/NATIVE_NETWORK_CALLSITE_EVIDENCE.md found a receive-side four-byte read followed by deserializeInt and a second read count derived from the returned integer. The send-side entry window contains serializeInt, compression and stream-write callsites. This is consistent with a four-byte big-endian length-prefix path, but remains a static candidate: no authorized wire fixture or runtime trace confirms the field relationship, active branch, or complete frame. In particular, do not equate the candidate with NetworkSettings.HeaderLength until its value and use are traced. The actual APK adapter remains blocked.
