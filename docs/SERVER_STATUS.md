# AOW server-only delivery status

**Current scope:** Build an independently operated server compatible with the unchanged authorized AOW Android client. **No Unity project, client rebuild, or new APK artifact is requested.**

## Implemented
- Local-only Python mock HTTP API and SQLite domain (server/mock.py) for account/character creation and movement.
- SQLite inventory domain: atomic grants, consumption, persistence, validation and concurrent-update tests.
- Offline APK structural inventory utility and candidate network string scanner (unverified hints, not confirmed endpoints).
- Synthetic-fixture tests and CI quality gate.

## Not implemented or not verified
- Production-quality authentication, accounts and secure sessions.
- Actual transport, framing, serialization, handshake, client version negotiation and protocol response schemas.
- APK connectivity, authoritative world simulation, real item catalog, combat/skills, shop, quests and matchmaking.
- Deployment of a compatible AOW game server. The mock HTTP API cannot be used by the original APK as-is.

## Acceptance criteria
1. Verify transport and message flow through authorized, redacted evidence from user-owned APK and local tests.
2. Implement and test a protocol adapter for the unchanged client.
3. Demonstrate client login -> player initialization -> map join -> movement -> inventory -> combat.
4. Deliver server source and reproducible deployment instructions with logs and tests.

**No APK output should be expected from this server-only repository.** CI reports tests, not an Android build.

## Privacy and security
This GitHub repository is public. Never commit original APK, proprietary extracted assets, player secrets, private network captures or credentials. Do not probe publisher infrastructure without authorization.
