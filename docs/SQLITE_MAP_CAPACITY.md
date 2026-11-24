# Durable synthetic map-capacity integrity

`SqliteMapCapacityStore` maintains a durable projection of configured
map limits and current membership over `map_position_snapshots`. All
identifiers, map IDs and capacity values in this module are synthetic.

## Transaction boundaries

- Capacity admission and membership reconciliation use `BEGIN IMMEDIATE`
  when they own the transaction, or a savepoint when called inside a protected
  caller transaction.
- `verify_integrity()` is diagnostic and read-only. It requires an idle
  connection, begins a deferred read transaction, pins one SQLite snapshot
  before running `quick_check` and the projection comparisons, and always
  rolls the transaction back.
- A concurrent writer may commit after the audit snapshot is released. A later
  audit then observes that newer database state independently.
- The audit never repairs projection drift. Operators must use a separately
  reviewed reconciliation procedure rather than silently changing live state.

## Validation

Run:

    python -m unittest discover -s tests -p 'test_sqlite_map_capacity*.py' -v

The audit snapshot regression pauses immediately before `PRAGMA quick_check`,
starts a second SQLite writer, and verifies that the writer cannot commit
between the pinned snapshot and the remaining consistency reads.

This is persistence correctness for the synthetic domain only. It does not
establish AOW map IDs, room capacity, movement packets, matchmaking semantics,
or APK compatibility.
