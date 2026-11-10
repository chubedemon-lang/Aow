# Synthetic session foundation

The repository contains process-local and durable session primitives, a shared character-ownership authorizer, and session-authorized map/player-state facades. None is an AOW APK login implementation.

## Process-local lifecycle

server/sessions.py implements a local-only session primitive:

- Tokens are generated using secrets.token_urlsafe(32); never log or commit tokens.
- A session maps to an internal account ID and expires according to a monotonic clock.
- require_character checks ownership in SQLite before permitting future character actions.
- Sessions are process-local and disappear on restart.
- No password verification, login HTTP route, real client handshake, transport framing, or AOW packet IDs are implemented.

## Durable SQLite token store

The store also exposes resolve_in_transaction() for callers that already hold a SQLite transaction. Pair it with BEGIN IMMEDIATE and SqliteCharacterAuthorizer.require_in_transaction() so session revocation cannot race between authorization and a protected state mutation. These methods do not open, commit, or roll back the caller's transaction.

server/sqlite_session_store.py is a separate persistence primitive:

- Stores only SHA-256 token digests, account IDs and epoch-based expiry timestamps.
- Supports issue, resolve, revoke and expired-session cleanup.
- Uses SQLite write transactions so concurrent revocation has one winner.
- Survives process restart when the same private database file is reopened.

It does not verify credentials. Tokens must only be issued after a trusted authentication layer has authenticated the account.

## Shared character authorizer

server/sqlite_character_authorizer.py resolves a durable session and checks that the requested integer character ID belongs to the resolved account in characters(id, account_id). Unknown and foreign IDs return the same SessionError. The authorizer and session store must share the same SQLite connection.

The synthetic schema does not expose ownership transfer. If transfers are introduced, they must be serialized with state mutations or the authorization boundary must be upgraded to a single transaction.

## Session-authorized synthetic domain facades

- server/sqlite_authorized_map_service.py checks ownership before map position create/read/enter/move/leave operations.
- server/sqlite_authorized_player_state_service.py checks ownership before player snapshot create/read/apply operations.
- Both are Python domain services only; neither adds an HTTP route, verifies passwords, or establishes AOW wire compatibility.
- Both retain the existing stores' revision and idempotency behavior after authorization.

## Integration gate

These facades are tested ownership boundaries for local synthetic data, not production authentication. Before production integration, require verified offline client protocol evidence, real account authentication, replay protection, rate limiting, transport security, durable or distributed session management, and authorization on every state-changing operation. Inventory and shop persistence remain separate domain primitives and are not yet wired into these facades or a verified APK adapter.

Run focused tests:

~~~sh
python -m unittest discover -s tests -p 'test_sessions.py' -v
python -m unittest discover -s tests -p 'test_sqlite_session_store.py' -v
python -m unittest discover -s tests -p 'test_sqlite_authorized_map_service.py' -v
python -m unittest discover -s tests -p 'test_sqlite_authorized_player_state_service.py' -v
~~~


## Synthetic credential boundary

`server/sqlite_account_auth_service.py` provides local PBKDF2-HMAC-SHA256 credential enrollment and verification for synthetic accounts. It issues a durable session only after re-reading the credential under `BEGIN IMMEDIATE`, using `SqliteSessionStore.issue_in_transaction` so credential verification and session insertion cannot be separated by a credential change. Enrollment is a trusted local setup operation; there is no HTTP route, rate limiter, APK password format, or APK login integration. See [SQLITE_ACCOUNT_AUTH_SERVICE.md](SQLITE_ACCOUNT_AUTH_SERVICE.md).
