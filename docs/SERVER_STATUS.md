# AOW server-only delivery status

**Current scope:** Build an independently operated server compatible with the unchanged authorized AOW Android client. No Unity project, client rebuild, or new APK artifact is requested.

## Implemented — local/synthetic only

- Local-only Python mock HTTP API and SQLite domain for synthetic account/character creation and movement.
- Synthetic SQLite inventory and player-state stores plus an atomic shop purchase store. A purchase debits player currency, grants inventory, advances both revisions, writes both mutation-ledger rows and a durable idempotency receipt in one `BEGIN IMMEDIATE` transaction; tests cover concurrent duplicate requests and rollback. Offer IDs, items and prices remain synthetic. These methods are not exposed as authenticated HTTP routes.
- Process-local session lifecycle and a separate durable SQLite bearer-session store. The durable store hashes opaque tokens, enforces expiry/revocation and survives process restarts, but it is not wired into the HTTP API and does not authenticate passwords or APK login.
- Separate durable SQLite player snapshots with optimistic revisions and idempotent mutation receipts. The store is not yet wired into account/character ownership or the HTTP API.
- SQLite reward/quest ledgers and synthetic map/movement/combat/quest modules with local regression tests.
- Offline APK inventory, protocol-candidate and IL2CPP metadata/type/codegen analysis tools. They make no network requests and do not modify the APK.
- GitHub Actions for synthetic server tests, protocol discovery tests and repository quality checks.

## Verified APK evidence

- The authorized APK is Unity 6 / IL2CPP, metadata version 31, with Addressables.
- Static IL2CPP registration analysis maps 165/165 metadata images to native codegen modules and 197,631 metadata method definitions to 197,631 native method-pointer slots.
- This is static registration evidence only. It does not establish the active transport, packet framing, byte order, message IDs on the wire, serializer field order, endpoint choice, handshake sequence or APK/server compatibility.

## Not implemented or not verified

- Production authentication, password verification, account registration/login routes, authorization and secure session integration.
- Verified transport, framing, serializer/deserializer contract, handshake, version negotiation or endpoint selection for the unchanged APK.
- APK connectivity or an end-to-end login → player initialization → map join → movement flow.
- Authoritative AOW item catalog, economy, combat/skills, quest rules, matchmaking or production anti-cheat.
- A production deployment bundle. The current mock API binds only to localhost and is deliberately not suitable for public exposure.

## Acceptance criteria

1. Verify transport and message flow through authorized, redacted evidence from the unchanged APK and local tests.
2. Implement and test a protocol adapter only after the real wire contract is known.
3. Integrate authenticated account ownership, durable sessions and player persistence behind that verified adapter.
4. Demonstrate client login → player initialization → map join → movement → inventory → combat with reproducible logs and fixtures.
5. Deliver server source and reproducible deployment instructions with smoke tests.

No APK output should be expected from this server-only repository. CI reports tests, not an Android build.

## Privacy and security

This GitHub repository is public. Never commit the original APK, proprietary extracted assets, player secrets, private network captures or credentials. Do not probe publisher infrastructure without authorization.
