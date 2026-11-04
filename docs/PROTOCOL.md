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

Add each discovery with APK version/hash, observation method, confidence, redacted evidence and a reproducible local test. Never publish tokens or other users' data.

## Offline candidate scanner safety and limits

Run `python -m tools.protocol_candidates /path/to/authorized.apk --output /private/local/report.json` on a locally held, authorized APK. This command reads the APK ZIP offline and makes **no network requests**. Reports must stay local and be reviewed before sharing.

The scanner intentionally emits only normalized URL **origins** (scheme, hostname and optional port) or host strings; it discards URL paths, queries, fragments, and userinfo, and suppresses strings containing credential-related keywords. This reduces accidental disclosure of embedded tokens, user identifiers and private paths. It is not a proof of safe publication: a hostname itself can still be sensitive, and a third-party analytics SDK can produce false positives.

The candidate output **cannot** establish which endpoint is used for gameplay, whether a hostname is active, or whether any particular transport or packet layout is supported. Never attempt to contact extracted hosts as part of this tool. Keep raw reports and APK bytes out of the public repository.

Before implementing an actual adapter, require independently verified and authorized evidence of client-facing transport/framing/handshake and a synthetic redacted test fixture with explicit provenance.
