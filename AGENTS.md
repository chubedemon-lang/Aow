# Codex / automation instructions — AOW server only

## User requirement
**Build a compatible independent source server for the existing AOW Android APK. Do NOT reconstruct the Unity project, rebuild APK, replace assets, or create a new client.**

## Priorities
1. Read docs/SERVER_STATUS.md and docs/PROTOCOL.md before changes. Keep verified facts separate from unverified hypotheses.
2. Obtain authorized offline APK bytes for static inspection when available. No invented IP, transport, packet IDs, schemas, encryption or gameplay claims.
3. Focus on the server: transport adapters, authentication/session management, persistent player state, map synchronization, authoritative game logic and tests.
4. Synthetic mock APIs remain explicitly labeled non-APK-compatible until wire-level tests prove compatibility.
5. PRs must include test cases and evidence. Prefer small, focused changes with real CI checks; merge only if green and no conflicts.
6. Never upload APK, decompiled code, proprietary assets, credentials or private captures to this public repo.
7. Never access, exploit, proxy or interfere with the publisher's infrastructure or other players without authorization.
8. No Android build artifacts are required for this server-only project. Deliver source server and deployment instructions only after compatibility is demonstrated.

## Immediate next actions
- Verify protocol candidate tooling, manifest parser and IL2CPP type evidence using authorized offline APK analysis.
- Establish a documented, redacted wire-contract ledger for login and player initialization.
- Build a protocol-adapter test harness with fixtures and no network dependency.
- Expand server domain with correctness, ownership and state transitions only as supported by evidence.
