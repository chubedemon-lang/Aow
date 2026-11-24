# AOW — Server-only reconstruction roadmap

## Scope
**Keep the original Android APK unchanged.** Do not rebuild Unity project, graphics, gameplay client, or APK. Develop an independent compatible server implementation for authorized private testing.

## Evidence gates
1. **Client protocol discovery:** identify endpoint configuration, transport (TCP/UDP/WebSocket/HTTP), serialization, encryption and handshake through static APK analysis and authorized local observations. Mark unknowns as unknown; do not assume packet IDs or server IPs.
2. **Session bootstrap:** reproduce server discovery/login/session/character selection flow on a local test endpoint, only after the actual wire contract is known.
3. **Player state:** account, character, stats, inventory, quests, map position, persistence.
4. **World simulation:** movement, entity replication, combat, skill effects, AI, matchmaking and rewards in order of verified dependencies.
5. **Content data:** independently constructed catalog and configuration, consistent with client contract and rights.
6. **Validation:** regression fixtures from authorized local tests, protocol compatibility suite, integration tests and deploy scripts.

## Proposed implementation boundaries (provisional)
- `server/`: transport adapters, packet codec, auth/session, game services, persistence.
- `tests/`: protocol fixtures, session flows, game rules.
- `docs/PROTOCOL.md`: evidence-backed message contracts and unknowns.
- `tools/`: read-only APK inspection and authorized local diagnostics.

No language, framework, database schema or wire codec should be selected as *verified* until requirements are established. An isolated mock server can be developed first without pretending it is APK-compatible.

## Risks / blockers
- Original server source is not in APK.
- Server address alone cannot recover server source or database.
- TLS/certificate pinning, signing, encryption, version checks or remote configuration may prevent an unchanged APK from connecting to a private endpoint; don't claim this solved without tests.
- Avoid unauthorized access to production infrastructure, users' traffic or publisher secrets.
- Repository is public; never commit proprietary APK/assets, credentials or private packet captures.

## Acceptance criteria
An unchanged, authorized client successfully completes login → character initialization → enter world → move → inventory/shop → combat against the independently hosted test server, verified with reproducible logs. Each stage must be tested before claiming completion.
