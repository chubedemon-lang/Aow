# Synthetic session foundation

The repository now contains process-local and durable session primitives, plus a small session-authorized map facade. None is an AOW APK login implementation.

## Process-local lifecycle

`server/sessions.py` implements a local-only session primitive:

- Tokens are generated using `secrets.token_urlsafe(32)`; never log or commit tokens.
- A session maps to an internal account ID and expires according to a monotonic clock.
- `require_character` checks ownership in SQLite before permitting future character actions.
- Sessions are process-local and disappear on restart.
- No password verification, login HTTP route, real client handshake, transport framing, or AOW packet IDs are implemented.

## Durable SQLite token store

`server/sqlite_session_store.py` is a separate persistence primitive:

- Stores only SHA-256 token digests, account IDs and epoch-based expiry timestamps.
- Supports issue, resolve, revoke and expired-session cleanup.
- Uses SQLite write transactions so concurrent revocation has one winner.
- Survives process restart when the same private database file is reopened.

It does not verify credentials. Tokens must only be issued after a trusted authentication layer has authenticated the account.

## Session-authorized synthetic map facade

`server/sqlite_authorized_map_service.py` composes the durable token store with the synthetic SQLite map-position store:

- Every map create/read/enter/move/leave operation resolves the bearer token.
- It checks `characters(id, account_id)` ownership before invoking the map store.
- Unknown and foreign character IDs return the same authorization error.
- Expired and revoked sessions cannot read or mutate map positions.
- The facade is a Python domain service only; it adds no HTTP route and does not authenticate passwords.

The current synthetic character schema does not support account ownership transfer. If that changes, transfer must be serialized with map mutations or the facade must be redesigned to authorize and mutate under one transaction.

## Integration gate

This facade is a tested ownership boundary for local synthetic data, not production authentication. Before production integration, require verified offline client protocol evidence, real account authentication, replay protection, rate limiting, transport security, durable or distributed session management, and authorization on every state-changing operation. The SQLite player-state, inventory and shop stores remain separate domain primitives and are not yet wired into a verified APK adapter.

Run focused tests:

```sh
python -m unittest discover -s tests -p 'test_sessions.py' -v
python -m unittest discover -s tests -p 'test_sqlite_session_store.py' -v
python -m unittest discover -s tests -p 'test_sqlite_authorized_map_service.py' -v
```
