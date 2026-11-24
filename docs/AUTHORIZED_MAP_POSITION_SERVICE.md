# Session-authorized synthetic map-position service

## Scope

`SqliteAuthorizedMapPositionService` joins the existing durable-session and character-ownership boundary to the synthetic SQLite map-position store. Every public operation holds `BEGIN IMMEDIATE` while resolving the bearer session, checking `characters(id, account_id)` ownership, and reading or mutating the position.

This is a server-domain integration only. It does not define AOW map IDs, coordinate units, spawn locations, movement speed, collision rules, packet fields, handshake/login messages, or APK compatibility. Map IDs and coordinates remain caller-supplied synthetic values. No HTTP route or public listener is registered.

Session tokens must only be issued after trusted account authentication. The service does not implement passwords, registration, or account creation. Ownership transfer is not supported.

## Operations

- `create_position(token, character_id)`: create an unplaced revision-zero position for an owned character.
- `get_position(token, character_id)`: read the durable position after session and ownership checks.
- `enter_map(token, character_id, request_id, expected_revision, map_id, x, y)`: enter a caller-selected synthetic map.
- `move(token, character_id, request_id, expected_revision, map_id, x, y)`: update a position on the currently occupied map.
- `leave_map(token, character_id, request_id, expected_revision, map_id)`: return the character to the unplaced state.

Every operation uses the same SQLite connection for sessions, ownership checks, and map persistence. Session revocation therefore serializes with a protected map transition. The map store uses a savepoint inside the authorization transaction, so a failed snapshot/receipt operation cannot leave a partial position mutation while the outer authorization transaction remains caller-owned.

## Validation

Run the focused suite:

    python -m unittest discover -s tests -p 'test_sqlite_authorized_map_position_service.py' -v

The Protocol Discovery workflow has a dedicated `authorized-map-position` job. Synthetic Server Tests and AOW Server Quality also run the full local test suite.

## Explicit non-claims

The service is not an AOW protocol adapter. It does not infer wire message IDs, packet framing, endpoint selection, handshake order, login semantics, original map identifiers, or movement rules. It must remain behind a verified future transport adapter and must not be exposed as a public game listener before authorized client-facing wire fixtures and end-to-end tests exist.
