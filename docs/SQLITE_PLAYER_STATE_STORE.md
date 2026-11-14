# Durable synthetic player state

`server/sqlite_player_state_store.py` persists server-side progression snapshots. It is a storage primitive only: it does not define AOW leveling rules, currency rules, inventory contents, movement, combat, or any client packet schema.

## Contract

- A character snapshot contains `character_id`, `level`, `experience`, `currency` and a monotonically increasing `revision`.
- `create` creates revision 0 and rejects duplicate character ids.
- `apply` requires an expected revision and a server-generated request id. It can apply an explicit level value plus experience/currency deltas; it never calculates AOW level thresholds.
- Each mutation and its idempotency receipt commit in one `BEGIN IMMEDIATE` transaction.
- A stale expected revision is rejected without changing the snapshot or writing a receipt.
- Replaying the same request id and exact payload returns the original result snapshot. Reusing the request id with a different payload is rejected.
- Separate SQLite connections serialize writers; concurrent identical requests produce one mutation and idempotent replays.

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
