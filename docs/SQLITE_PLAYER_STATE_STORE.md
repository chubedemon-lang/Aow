# Durable synthetic player state

`server/sqlite_player_state_store.py` persists server-side progression snapshots. It is a storage primitive only: it does not define AOW leveling rules, currency rules, inventory contents, movement, combat, or any client packet schema.

## Contract

- A character snapshot contains `character_id`, `level`, `experience`, `currency` and a monotonically increasing `revision`.
- `create` creates revision 0 and rejects duplicate character ids.
- `apply` requires an expected revision and a server-generated request id. It can apply an explicit level value plus experience/currency deltas; it never calculates AOW level thresholds.
- Standalone `create` and `apply` operations use `BEGIN IMMEDIATE` so the snapshot and its receipt commit atomically.
- When called inside a caller-owned transaction, each operation uses a private SQLite savepoint. A failed operation rolls back only its own partial writes; a successful operation releases its savepoint but leaves the outer transaction open for the caller to commit or roll back.
- A stale expected revision is rejected without changing the snapshot or writing a receipt.
- Replaying the same request id and exact payload returns the original result snapshot. Reusing the request id with a different payload is rejected.
- The constructor accepts only an exact built-in `sqlite3.Connection`; subclasses are rejected before custom connection hooks can run.
- Character and request identifiers must be exact built-in strings, non-empty after whitespace-only validation, and at most 128 characters. Existing non-empty identifiers with surrounding whitespace remain unchanged for compatibility. String subclasses are rejected before `strip`, length, or hash hooks can run.
- Separate SQLite connections serialize writers; concurrent identical requests produce one mutation and idempotent replays.
- Schema bootstrap and the legacy `baseline_version` migration run in one `BEGIN IMMEDIATE` transaction; a rejected schema leaves no partial tables or migration behind.
- The constructor validates exact column names, declared types, nullability, primary-key layout and defaults for snapshots, creation receipts and mutation receipts. It also validates the named non-unique mutation-history index and its ordered columns before reusing an existing database.
- Legacy snapshots are migrated only when their pre-migration column layout exactly matches the supported five-column schema; malformed or extra-column layouts are rejected rather than altered.

## Integrity audit

- `verify_integrity` requires an idle connection and pins one deferred SQLite read snapshot before checking snapshots, creation receipts, and mutation history.
- Concurrent commits are observed either wholly before or wholly after the audit snapshot; a single audit cannot combine rows from different database revisions.
- The read transaction is always rolled back on success or failure, leaving the connection idle for subsequent operations.
- This verifies local consistency only. It does not establish AOW protocol semantics or provide cryptographic tamper resistance.

## Authorization boundary

Authenticate the account and verify character ownership before calling this store. Never accept a client-selected account id or trust a client-supplied request id without namespacing it to an authenticated server-side operation. Every state-changing route must authorize the account/character pair before calling `apply`. Keep the database private and back it up.

This module is not yet wired into the HTTP server or existing in-memory `PlayerState` / `PlayerProfiles` services. It does not prove APK compatibility or replace a verified protocol adapter.

Run the focused and full suites:

```sh
python -m unittest discover -s tests -p 'test_sqlite_player_state_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK, native library, proprietary game assets, endpoint secrets, or packet captures belong in the public repository.
