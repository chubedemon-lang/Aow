# Durable synthetic SQLite inventory

`server/sqlite_inventory_store.py` is an independent persistence primitive for the synthetic server domain. It is **not** an AOW APK item catalog, inventory packet contract, or proof of client compatibility.

## Behavior

- Persists inventory headers, item quantities and mutation receipts in SQLite.
- Uses caller-supplied synthetic item IDs, capacity and stack limits; defaults are test/domain defaults, not values inferred from AOW.
- Applies a bounded batch of signed item deltas atomically.
- Aggregates repeated item IDs and sorts the canonical payload so an exact retry is order-independent.
- Guards mutations with an expected inventory revision.
- Stores an idempotency receipt in the same `BEGIN IMMEDIATE` transaction as the inventory change.
- An exact retry returns the original committed snapshot, even after later mutations.
- Reusing a request ID for a different character, expected revision or payload is rejected.
- Rejects underflow, stack overflow, capacity overflow, empty net mutations and oversized batches without changing state.
- Supports reopening the same private SQLite database file.

## Integration boundary

This module is not wired into `server/mock.py`, does not authenticate accounts, and does not establish character ownership. A trusted caller must authenticate the account, verify character ownership, and authorize every mutation before invoking the store. Never expose arbitrary item grants or caller-selected character IDs as public routes.

The values used here are synthetic. Do not substitute them for original AOW item IDs, stack rules, slot layout or economy without authorized evidence.

## Tests

Run the focused tests and the full repository suite:

```sh
python -m unittest discover -s tests -p 'test_sqlite_inventory_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK bytes, proprietary assets, credentials, extracted native binaries or private packet captures belong in this public repository.
