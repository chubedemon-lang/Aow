# Session-authorized synthetic player-state service

## Scope

`SqliteAuthorizedPlayerStateService` composes the durable SQLite session store,
the shared `SqliteCharacterAuthorizer`, and the synthetic durable player-state
store. It authorizes snapshot creation, reads and mutations against
`characters(id, account_id)` before calling the player-state store.

This is a local domain integration only. It does not implement AOW login,
player-initialization packets, original-game EXP/level rules, or APK
compatibility. It adds no HTTP route and does not verify passwords.

## Authorization boundary

- A trusted authentication layer must verify the account before issuing a
  token through `service.sessions.issue(account_id)`.
- Only a SHA-256 token digest is persisted by the session store.
- Every create/read/apply operation resolves the session and checks ownership.
- Unknown and foreign character IDs return the same authorization error.
- Expired and revoked sessions cannot read or mutate snapshots.
- The facade accepts the synthetic integer character ID and maps it to the
  string ID used by the player-state persistence primitive.

The current synthetic character schema does not expose ownership transfer. If
that changes, transfer must be serialized with state mutations or the shared
authorizer must be upgraded to a single-transaction ownership boundary.

## Validation

Run:

    python -m unittest tests.test_sqlite_authorized_player_state_service -v

Tests cover owner create/read/apply, cross-account denial, unknown-character
error equivalence, expiry, revocation, invalid IDs, idempotent replay,
duplicate initialization and missing-schema fail-closed behavior.

## Explicit non-goals

- No AOW login or player-init wire format.
- No authoritative EXP, level, currency or progression rules.
- No production password authentication, TLS, rate limiting or HTTP route.
- No APK modification, Unity/client project or APK build.

Do not expose the localhost mock API or treat this synthetic facade as
production authentication.
