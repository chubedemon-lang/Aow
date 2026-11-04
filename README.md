# AOW — independent server reconstruction

**Project scope: server source only. Keep the original Android APK unchanged.**
This repository does not rebuild Unity, modify APKs, or provide game client artifacts.

## Current reality
- A synthetic, localhost-only Python/SQLite server prototype implements character creation, movement, and transactional inventory domain methods.
- Offline APK inventory and network-string candidate tools are included.
- The actual AOW protocol (transport, framing, authentication, handshake and schemas) is **not yet established**. The mock server does not connect the original APK.
- No full game server is ready. See docs/SERVER_STATUS.md.

## Reproducible tests
Run from the repository root:
    python -m unittest discover -s tests -v

Run the intentionally synthetic local API:
    python -m server.mock --db aow_mock.sqlite3 --port 8765

Its HTTP endpoints are fixtures, not original AOW messages. Do not expose it publicly.

## Server roadmap
1. Analyze the user-provided authorized APK offline; verify transport, packet/codec, endpoint discovery and authentication flow.
2. Document evidence in docs/PROTOCOL.md. Never treat candidate strings as confirmed endpoints.
3. Implement actual protocol adapter and secure sessions.
4. Add player initialization, world/map sync, inventory, combat, shop, missions and persistence according to verified client contracts.
5. Verify end-to-end operation against the unchanged authorized APK; provide deployment scripts, CI and server logs.

## Safety / rights
This repository is public. Do not commit original APK, proprietary extracted assets, player data, keys, credentials or private traffic captures. Do not access official game infrastructure beyond authorized normal use.
