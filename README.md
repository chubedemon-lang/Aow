# AOW — independent server reconstruction

**Project scope: server source only. Keep the original Android APK unchanged.**
This repository does not rebuild Unity, modify APKs, or provide game client artifacts.

## Current reality
- A synthetic, localhost-only Python/SQLite server prototype implements character creation, movement, and transactional inventory domain methods.
- Offline APK inventory and network-string candidate tools are included.
- Read-only native inspection has identified primitive serializer behavior (big-endian integer/code-unit operations, UTF-16 code-unit strings, and one-byte boolean/byte paths). An isolated tested codec exists, but it is not connected to network handlers.
- The actual AOW protocol (active transport, framing, authentication, handshake, message IDs and message schemas) is **not yet established**. The mock server does not connect the original APK.
- No full game server is ready. See docs/SERVER_STATUS.md.

## Local synthetic runbook
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for server layering and protocol evidence gates, and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the localhost-only prototype startup and read-only SQLite preflight. Neither is a production deployment or APK compatibility claim.

## Reproducible tests
Run from the repository root:
    python -m unittest discover -s tests -v

Run the intentionally synthetic local API:
    python -m server.mock --db aow_mock.sqlite3 --port 8765

Its HTTP endpoints are fixtures, not original AOW messages. Do not expose it publicly.

## Server roadmap
1. Analyze the user-provided authorized APK offline; verify transport, outer framing, message dispatch and authentication flow.
2. Document evidence in docs/PROTOCOL.md. Never treat candidate strings as confirmed endpoints or primitive encoding as a complete message schema.
3. Implement an actual protocol adapter and secure sessions only after the complete client-facing wire contract is independently reproduced.
4. Add player initialization, world/map sync, inventory, combat, shop, missions and persistence according to verified client contracts.
5. Verify end-to-end operation against the unchanged authorized APK; provide deployment scripts, CI and server logs.

## Safety / rights
This repository is public. Do not commit original APK, proprietary extracted assets, player data, keys, credentials or private traffic captures. Do not access official game infrastructure beyond authorized normal use.
