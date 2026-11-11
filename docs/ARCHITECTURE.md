# Server architecture and evidence gates

**Scope: reconstruct the server only. The original Android APK remains unchanged.**
This document describes the repository's architecture and the conditions under which
synthetic modules may be connected to a future AOW transport adapter. It does not
claim that the current server accepts the original client.

## 1. Non-negotiable boundaries

- Do not modify, rebuild, repackage or replace the original APK.
- Do not create a Unity project or another game client.
- Do not commit the APK, extracted proprietary assets, native libraries, raw private
  traffic, player data, credentials or endpoint values to this public repository.
- Do not probe or contact extracted endpoints or official game infrastructure to
  compensate for missing local evidence.
- Treat synthetic IDs, maps, items, prices, combat rules and quest rules as test data,
  not as recovered AOW semantics.
- Keep unknown protocol behavior disabled. A passing synthetic test is not evidence
  of wire compatibility.

## 2. Layering

The intended dependency direction is:

\`\`\`text
Authorized offline evidence (private workspace)
                 |
                 v
Redacted evidence manifest + provenance checks
                 |
                 v
Protocol contract registry and ordered evidence gates
                 |
        only after proof
                 v
AOW transport / frame / message adapter
                 |
                 v
Session and authenticated account ownership
                 |
                 v
Character bootstrap and authoritative player state
                 |
                 v
World / map / movement / inventory / shop / combat / quest
                 |
                 v
Persistence, audit, backup, monitoring and deployment
\`\`\`

The evidence registry and gates are control-plane metadata. They must not infer a
packet field from a method name, a candidate string, a primitive serializer, or a
synthetic fixture. The future adapter must consume a versioned contract whose
individual claims carry provenance and confidence.

## 3. Existing implementation boundaries

| Area | Current implementation | Boundary |
|---|---|---|
| HTTP mock | \`server.mock\` | Local synthetic API; IPv4 loopback only |
| Runtime safety | \`server.runtime_safety\` | Rejects non-loopback bind configuration |
| Database preflight | \`tools.server_preflight\` | Read-only \`synthetic-v1\` schema check; not production readiness |
| Authentication | Local PBKDF2/account primitives and durable session stores | Synthetic domain services; not the APK login flow |
| Character/player state | SQLite services with ownership, revisions and receipts | Synthetic defaults and state transitions |
| Map/movement | SQLite map-position services | No recovered AOW map IDs, coordinates or movement packets |
| Inventory/shop | Transactional SQLite services | Synthetic item IDs, catalog and economy |
| Combat/quest | Deterministic local domain services and award ledgers | No recovered AOW skills, battle messages or quest rules |
| Primitive codec | Isolated known-vector serializer operations | Not a frame decoder or message schema |
| Native analysis | Offline IL2CPP/ARM64 evidence tooling | Static analysis only; no runtime trace implied |

Keep domain services independent from network handlers. Do not add client-facing
routes to the synthetic HTTP mock as a shortcut to compatibility.

## 4. Protocol evidence gate

The AOW adapter stays disabled until the following are established from the same
authorized APK build and reproducible local evidence:

1. Active transport and connection lifecycle.
2. Outer framing: header length, length semantics, byte order, maximum frame size,
   fragmentation and coalescing behavior.
3. Compression or encryption activation, order, parameters and error handling.
4. Message dispatch and wire message IDs.
5. Handshake/version negotiation and failure paths.
6. Login request/response field order, encoding, identity binding and session lifecycle.
7. Character initialization, map join and movement messages.

For every claim, record:

- APK fingerprint/build identity in private evidence storage;
- source method/type and the static or dynamic observation that supports it;
- whether the evidence is static, runtime-observed or fixture-reproduced;
- confidence, unresolved alternatives and explicit non-claims;
- a redacted local fixture or known-vector test when bytes are available.

Static callsite order is not automatically serialization order. A primitive codec
only describes primitive operations. A candidate frame decoder must not be promoted
to the active protocol until a real authorized fixture round-trips independently.

## 5. Adapter integration sequence

Once the gate is satisfied, implement small independently testable layers:

1. Bounded stream reader/writer with fragmentation, coalescing, EOF and size-limit tests.
2. Frame parser/encoder using only verified header semantics.
3. Compression/encryption wrapper only when activation and parameters are verified.
4. Message dispatcher with an explicit versioned message-ID registry.
5. Handshake and version negotiation state machine.
6. Login/session adapter with expiry, revocation, replay and account-ownership tests.
7. Character bootstrap and map/movement synchronization.
8. Inventory, shop, combat and quest handlers backed by authoritative services.

Every handler must reject malformed, oversized, out-of-state and unauthorized input.
No handler may trust a client-supplied character/account ownership claim.

## 6. Persistence and operations

- Keep SQLite domain transactions atomic and preserve caller-owned transaction
  boundaries.
- Use migrations with explicit versions; never silently rewrite an existing player DB.
- Backups must be consistent, verifiable and restore-tested before any non-local
  deployment is considered.
- Keep secrets outside the repository and rotate keys through an operator-controlled
  process.
- Add structured logs without credentials, tokens, private packet bytes or player
  secrets.
- The current mock must remain loopback-only. Do not deploy it to a public VPS or
  expose it through a reverse proxy.

## 7. Acceptance criteria

A release may be described as compatible only after the unchanged authorized APK
completes a reproducible end-to-end flow against a separately operated test server:

\`connect → handshake → login → character bootstrap → map join → movement\`

Then verify inventory, shop, combat and quest flows with authorized fixtures and
client observations. Preserve server logs, fixture hashes and CI results without
publishing private bytes or secrets.

Until then, describe the repository accurately as a synthetic server prototype plus
offline evidence tooling. Do not claim full server completion or APK compatibility.
