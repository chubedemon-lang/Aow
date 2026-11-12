# AOW server-only delivery status

**Current scope:** Build an independently operated server compatible with the unchanged authorized AOW Android client. No Unity project, client rebuild, or new APK artifact is requested.

## Implemented — local/synthetic only

- Local-only Python mock HTTP API and SQLite domain for synthetic account/character creation and movement.
- The synthetic mock CLI now fails closed unless bound to a literal IPv4 loopback address. A read-only preflight checks the existing mock SQLite integrity, foreign keys and required tables/columns; it explicitly reports that the prototype is neither APK-compatible nor production-ready. See docs/DEPLOYMENT.md.
- Synthetic SQLite inventory and player-state stores plus an atomic shop purchase store. A purchase debits player currency, grants inventory, advances both revisions, writes both mutation-ledger rows and a durable idempotency receipt in one BEGIN IMMEDIATE transaction; tests cover concurrent duplicate requests and rollback. Offer IDs, items and prices remain synthetic. These methods are not exposed as authenticated HTTP routes.
- Process-local session lifecycle and a separate durable SQLite bearer-session store. The durable store hashes opaque tokens, enforces expiry/revocation and survives process restarts. A separate local synthetic PBKDF2 account-auth service verifies enrolled credentials and issues a durable session after an in-transaction credential recheck; it can be composed with an optional persistent HMAC-keyed username failure limiter that clears atomically on success. The limiter is not a source-IP/network control; there is no HTTP route and this is not the APK login protocol.
- SqliteAuthorizedCharacterService resolves a durable session and creates, lists or reads one synthetic character per account; character creation and zero-balance wallet initialization commit together after validating unique ownership and foreign-key constraints. The default map, origin coordinates and wallet balance are synthetic placeholders, not AOW character-init rules.
- Shared SqliteCharacterAuthorizer resolves a durable session and checks characters.account_id ownership for a synthetic character ID.
- SqliteAuthorizedShopService holds BEGIN IMMEDIATE across in-transaction session resolution, characters.account_id ownership and the complete debit/grant/receipt transaction; the low-level shop store joins the caller-owned transaction. This serializes revocation with purchases and receipt replay. It remains a local domain service, not an authenticated HTTP route or AOW shop contract.
- SqliteAuthorizedInventoryService holds BEGIN IMMEDIATE across in-transaction session resolution, characters.account_id ownership and inventory create/read/apply; low-level store methods join the caller-owned transaction and do not commit it. This serializes revocation with protected inventory operations, including receipt replay. It remains a local domain service, not an authenticated HTTP route or AOW item contract.
- SqliteAuthorizedMapService holds BEGIN IMMEDIATE across session resolution, character ownership and map-position create/read/enter/move/leave; its low-level store joins the caller-owned transaction so revocation cannot race map state operations.
- SqliteAuthorizedPlayerStateService holds BEGIN IMMEDIATE across session resolution, character ownership and player snapshot create/read/apply; its low-level store joins the caller-owned transaction. Map and player-state services remain local Python domain services, not authenticated HTTP routes; ownership transfer is not supported.
- SqliteAuthorizedQuestAwardService holds BEGIN IMMEDIATE across session resolution, character ownership and synthetic reward-ledger grants/balance reads. Its isolated reward ledger remains available for existing tests but is not authoritative inventory and does not validate quest completion.
- SqliteAuthorizedQuestInventoryAwardService now grants one synthetic quest item into the existing inventory and writes a unique per-character/quest/item receipt in the same BEGIN IMMEDIATE transaction. Exact retries return the original inventory snapshot; a second request for the same quest/item is rejected. The trusted quest domain must validate completion before calling it. This is not an AOW quest contract and is not exposed as an HTTP route.
- Separate durable SQLite player snapshots with optimistic revisions and idempotent mutation receipts. SqlitePlayerStateStore.verify_integrity() now audits snapshot ranges, receipt ownership, contiguous revision history and receipt-to-snapshot consistency without writes; its baseline limitation is documented in docs/PLAYER_STATE_INTEGRITY.md. The store remains a domain persistence primitive and does not establish AOW player initialization or progression rules.
- Separate durable SQLite synthetic map-position snapshots with map-bound enter/move/leave transitions, optimistic revisions and idempotent receipts. The underlying store remains a persistence primitive and does not establish AOW map or movement rules.
- SQLite reward/quest ledgers and synthetic map/movement/combat/quest modules with local regression tests.
- A session-authorized SQLite combat facade persists deterministic synthetic battle snapshots and turn events with optimistic revisions and idempotent receipts; actor selection remains a trusted server-coordinator responsibility, and no HTTP/AOW route is exposed.
- Offline APK inventory, protocol-candidate and IL2CPP metadata/type/codegen analysis tools. They make no network requests and do not modify the APK.
- A bounded generic byte-stream buffer supports fragmented/coalesced chunks, exact reads, peeking, EOF and atomic capacity enforcement. It does not open sockets, parse frames or assume an AOW header.
- An isolated primitive payload codec mirrors the statically inspected SimpleSerializer/SimpleDeserializer operations: big-endian 16/32/64-bit values, UTF-16 code-unit strings, and one-byte boolean/byte values. Synthetic known-vector tests cover its behavior. It is not connected to network handlers and does not implement a packet frame or message schema.
- GitHub Actions for synthetic server tests, protocol discovery tests and repository quality checks.

## Verified APK evidence

- The authorized APK is Unity 6 / IL2CPP, metadata version 31, with Addressables.
- Static IL2CPP registration analysis maps 165/165 metadata images to native codegen modules and 197,631 metadata method definitions to 197,631 native method-pointer slots.
- Private read-only native method-body inspection provides static evidence for primitive serializer byte order and string/boolean behavior, as documented in docs/AOW_PRIMITIVE_SERIALIZATION.md.
- This remains primitive payload evidence only. It does not establish active transport, outer framing, message IDs on the wire, LoginRequest field order, endpoint choice, handshake sequence or APK/server compatibility.

## Not implemented or not verified

- Production authentication, account registration/login routes, source/network abuse controls, transport security and secure session integration. The current PBKDF2 and optional per-username limiter are synthetic local primitives only.
- Verified transport, outer framing, complete message serializer/deserializer contract, handshake, version negotiation or endpoint selection for the unchanged APK.
- APK connectivity or an end-to-end login → player initialization → map join → movement flow.
- Authoritative AOW item catalog, economy, combat/skills, quest rules, matchmaking or production anti-cheat.
- A production deployment bundle. The current mock API binds only to localhost and is deliberately not suitable for public exposure.

## Acceptance criteria

1. Verify transport and message flow through authorized, redacted evidence from the unchanged APK and local tests.
2. Implement and test an actual protocol adapter only after the real wire contract is known.
3. Integrate authenticated account ownership, durable sessions and player persistence behind that verified adapter.
4. Demonstrate client login → player initialization → map join → movement → inventory → combat with reproducible logs and fixtures.
5. Deliver server source and reproducible deployment instructions with smoke tests.

No APK output should be expected from this server-only repository. CI reports tests, not an Android build.

## Privacy and security

This GitHub repository is public. Never commit the original APK, proprietary extracted assets, player secrets, private network captures or credentials. Do not probe publisher infrastructure without authorization.
