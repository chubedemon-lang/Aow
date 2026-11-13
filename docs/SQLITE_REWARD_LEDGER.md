# Synthetic durable reward ledger

`server/sqlite_reward_ledger.py` is a standalone SQLite persistence experiment. It is **not** a verified AOW packet format, not connected to the in-memory inventory/quest adapters, and not production-ready.

A unique `request_id` protects identical retries: receipt insertion and balance increment share one `BEGIN IMMEDIATE` transaction. A replay with a different payload raises `RewardConflict`. Receipts survive reopening the database.

## Numeric integrity

Reward quantities and balances are bounded to SQLite's signed 64-bit INTEGER range. Before crediting a balance, the ledger reads the current stored value inside the same write transaction, rejects legacy REAL/non-integer values, and checks that the addition cannot overflow. The receipt and quest award key roll back together if the balance would exceed the limit. New tables also enforce integer storage with CHECK constraints.

Existing databases created before these CHECK constraints are not rewritten. The runtime validation still rejects a non-integer legacy balance before applying a new grant; inspect and repair such a row through an operator-controlled migration rather than coercing it silently.

The ledger constructor requires an idle SQLite connection before creating its tables. `grant_once` also rejects an active caller transaction before issuing `BEGIN IMMEDIATE`; it does not commit or roll back caller-owned work. This avoids accidental schema commits and preserves transaction ownership.

Limitations: callers must generate stable, authenticated idempotency keys, authorize the quest reward and player ownership, and enforce a single award per quest with a unique (player, quest, reward) constraint before production use. There are no item capacity limits, reward catalog checks, migration tooling, concurrency stress tests, or server network endpoints. Do not accept untrusted client-supplied reward quantities.

Run `python -m unittest tests.test_sqlite_reward_ledger -v`, `python -m unittest tests.test_quest_award_ledger -v`, or `python -m unittest discover -s tests`. No APK changes or client compatibility claims.
