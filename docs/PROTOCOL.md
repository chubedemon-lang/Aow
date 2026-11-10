# AOW protocol evidence ledger

**Current status: unknown.** Unity IL2CPP and Addressables have been identified, but no verified transport, packet structure, server host, authentication flow, or wire captures are available here.

| Component | Verified evidence | Status |
|---|---|---|
| Endpoint discovery | Not established | Unknown |
| Transport | Not established | Unknown |
| Handshake | Not established | Unknown |
| Serialization | Not established | Unknown |
| Compression/encryption | Not established | Unknown |
| Login/session | Not established | Unknown |
| Player initialization | Not established | Unknown |
| World synchronization | Not established | Unknown |

Add each discovery with APK version/hash, observation method, confidence, redacted evidence and a local test. Never publish tokens or other users' data.

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

Observed message-related identifier strings include `LoginRequest`, `LoginAnswer`, `SessionRestoreRequest`, `SessionRestoreAnswer`, `LoginToBattleRequest`, `LoginToBattleAnswer`, `RegistrationRequest`, `RegistrationAnswer`, `CheckSocket`, and `Ping`. Each of those ten identifiers has matching `STSerializer` and `STDeserializer` suffix strings in the metadata string heap.

**Interpretation limit:** these are static metadata string identifiers, not recovered method bodies or a wire specification. They do not establish message IDs, field layouts, payload encoding, framing, byte order, transport choice, endpoint selection, application handshake order, authentication semantics, or compatibility with the APK. In particular, names such as `NetworkSocket` and `TransportType` do not prove TCP, UDP, or any particular protocol. No extracted host/IP values are published and no remote host was contacted.

Reproduce the allowlisted inventory locally:

```bash
python tools/il2cpp_metadata_inventory.py /path/to/authorized/aow.apk --output /private/local/il2cpp_protocol_inventory.json
```

The tool reads only the bounded metadata member, validates the v31 header/string-heap bounds, emits an allowlisted identifier summary, and makes no network requests. Keep APK bytes and local reports outside this public repository. See [the detailed offline inventory](IL2CPP_PROTOCOL_IDENTIFIER_INVENTORY.md).
