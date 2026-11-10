# Synthetic session foundation

The repository now contains two distinct session primitives. Neither is an AOW APK login implementation.

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

It is not wired into the mock HTTP API, does not verify credentials, and must only be called after a trusted authentication layer has authenticated the account. Every state-changing operation still requires account/character ownership authorization.

## Integration gate

Before production integration, require verified offline client protocol evidence, real account authentication, replay protection, rate limiting, transport security, durable or distributed session management, and authorization on every state-changing operation. The SQLite player-state store is also a separate primitive and is not yet connected to session ownership.

Run focused tests:

```sh
python -m unittest discover -s tests -p 'test_sessions.py' -v
python -m unittest discover -s tests -p 'test_sqlite_session_store.py' -v
```
