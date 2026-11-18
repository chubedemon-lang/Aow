# Read-only SQLite domain audit

`tools.sqlite_domain_audit` checks existing synthetic inventory, quest-inventory-award, player-state, map-position and reward-ledger stores in one pass.

The inventory-backed quest award store and the generic reward ledger are separate persistence models. The quest-award audit verifies that each quest receipt matches the exact inventory mutation receipt derived from its request ID. It also rejects unpaired mutations in the reserved `quest-` inventory-mutation namespace. The inventory audit independently replays the complete inventory mutation history.

The generic reward ledger remains a separate synthetic grant/receipt prototype. It is not assumed to be wired into gameplay.

It opens the database using SQLite `mode=ro` and enables `PRAGMA query_only`. It does not construct stores through their normal constructors: those constructors contain `CREATE TABLE/INDEX IF NOT EXISTS` statements and commit, so the audit deliberately bypasses them and invokes only each store's read-only `verify_integrity()` method.

## Run

```sh
python -m tools.sqlite_domain_audit --db ./var/aow_domain.sqlite3
```

Example shape of a successful report:

```json
{
  "audits": {
    "inventory": {"items": 2, "mutations": 2, "snapshots": 1},
    "quest_inventory_awards": {"awards": 1, "linked_inventory_mutations": 1},
    "map_position": {"mutations": 3, "snapshots": 1},
    "player_state": {"mutations": 2, "snapshots": 1},
    "reward_ledger": {"balances": 1, "receipts": 2, "quest_award_keys": 0}
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
- Rejects a quest-award table unless the complete inventory snapshot, item and mutation tables are present.
- Rejects reserved `quest-` inventory mutations when the quest-award table is absent.
- Verifies canonical quest-award payloads and snapshots against their matching inventory mutation receipt.
- Rejects orphaned quest-award receipts and unpaired mutation IDs in the reserved `quest-` namespace.
- Runs SQLite and foreign-key checks before store-level audits.
- Reports `no_domain_stores` when the file contains none of the recognized domain tables; this is not the same as an audited domain database.
- Returns exit code `2` and a compact JSON `blocked` result when an audit cannot be completed.

The tool emits aggregate counts only. It does not print character IDs, item IDs, mutation payloads, tokens or database contents.

## CI coverage

The Protocol Discovery workflow runs a dedicated `sqlite-domain-audit` job for this tool, its tests, and its documentation. The job compiles the auditor and quest-award store, then runs the focused read-only regression suite independently of the broader server test suite.

## Scope

These stores are synthetic persistence primitives. A successful audit does not establish AOW item IDs, quest IDs, map IDs, movement rules, packet framing, login semantics or APK compatibility. The audit is a consistency check, not cryptographic tamper evidence, and never repairs data.

Keep SQLite databases and backups private. Do not commit user data, credentials, APK bytes, extracted assets or packet captures to this public repository.
