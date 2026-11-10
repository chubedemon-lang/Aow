# Read-only SQLite domain audit

`tools.sqlite_domain_audit` checks existing synthetic inventory, player-state and map-position stores in one pass.

It opens the database using SQLite `mode=ro` and enables `PRAGMA query_only`. It does not construct stores through their normal constructors: those constructors contain `CREATE TABLE/INDEX IF NOT EXISTS` statements and commit, so the audit deliberately bypasses them and invokes only each store's read-only `verify_integrity()` method.

## Run

```sh
python -m tools.sqlite_domain_audit --db ./var/aow_domain.sqlite3
```

Example shape of a successful report:

```json
{
  "audits": {
    "inventory": {"items": 2, "mutations": 4, "snapshots": 1},
    "map_position": {"mutations": 3, "snapshots": 1},
    "player_state": {"mutations": 2, "snapshots": 1}
  },
  "foreign_key_violations": 0,
  "sqlite_integrity": "ok",
  "status": "ok"
}
```

Counts above are illustrative, not data from a production database.

## Fail-closed behavior

- Rejects `:memory:`, missing files, directories, symlinks and unreadable/corrupt SQLite files.
- Rejects a partial schema for any recognized domain store.
- Runs SQLite and foreign-key checks before store-level audits.
- Reports `no_domain_stores` when the file contains none of the recognized domain tables; this is not the same as an audited domain database.
- Returns exit code `2` and a compact JSON `blocked` result when an audit cannot be completed.

The tool emits aggregate counts only. It does not print character IDs, item IDs, mutation payloads, tokens or database contents.

## Scope

These stores are synthetic persistence primitives. A successful audit does not establish AOW item IDs, map IDs, movement rules, packet framing, login semantics or APK compatibility. The audit is a consistency check, not cryptographic tamper evidence, and never repairs data.

Keep SQLite databases and backups private. Do not commit user data, credentials, APK bytes, extracted assets or packet captures to this public repository.
