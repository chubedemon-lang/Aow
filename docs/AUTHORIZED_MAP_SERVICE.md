# Session-authorized synthetic map service

## Scope

SqliteAuthorizedMapService composes the durable SQLite bearer session store,
the shared SqliteCharacterAuthorizer, and the synthetic SQLite map-position
store. It authorizes each map read or mutation by resolving a server-issued
session and checking the characters(id, account_id) row before calling the
map store.

This is a local server-domain integration only. It is not the AOW APK login
protocol, does not verify passwords, does not expose an HTTP route, and does
not define original-game character IDs, map IDs, coordinate units or movement
rules.

## Setup

The caller must initialize the repository's synthetic character schema first.
The supplied SQLite connection is shared by the session and map stores and
must be idle when the service is constructed and before each operation.

A trusted authentication layer must verify an account before issuing a token
through service.sessions.issue(account_id). The session store persists only
a SHA-256 digest of the opaque token. Never log or commit the token.

## Authorization

Every create_position, get_position, enter, move and leave call resolves the
token, then checks that the requested integer character ID belongs to the
resolved account. Unknown and foreign character IDs return the same
SessionError to avoid a character-existence oracle. Expired and revoked
tokens are rejected before the map store is called.

The current synthetic character schema does not support account ownership
transfer. If ownership transfer is introduced, it must be serialized with map
mutations or the shared authorizer must be redesigned to authorize and mutate
under one transaction.

## Validation

Run:

    python -m unittest tests.test_sqlite_authorized_map_service -v

Tests cover owner lifecycle, cross-account denial for every operation,
unknown-character error equivalence, expiry, revocation, invalid IDs,
idempotent replay, duplicate initialization and missing-schema fail-closed
behavior.

## Explicit non-goals

- No APK packet parsing, handshake, login route or wire compatibility.
- No production password authentication, TLS, rate limiting or public API.
- No original AOW map catalog, movement constraints or collision rules.
- No Unity/client project and no APK modification or build.

Do not expose the localhost mock API or treat this synthetic facade as a
production authentication system.
