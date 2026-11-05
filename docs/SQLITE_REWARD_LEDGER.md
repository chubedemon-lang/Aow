# Synthetic durable reward ledger

`server/sqlite_reward_ledger.py` is a standalone SQLite persistence experiment. It is **not** a verified AOW packet format, not connected to the in-memory inventory/quest adapters, and not production-ready.

A unique `request_id` protects identical retries: receipt insertion and balance increment share one `BEGIN IMMEDIATE` transaction. A replay with a different payload raises `RewardConflict`. Receipts survive reopening the database.

Limitations: callers must generate stable, authenticated idempotency keys, authorize the quest reward and player ownership, and enforce a single award per quest with a unique (player, quest, reward) constraint before production use. There are no item capacity limits, reward catalog checks, migration tooling, concurrency stress tests, or server network endpoints. Do not accept untrusted client-supplied reward quantities. SQLite connections must not already be in a transaction when calling `grant_once`.

Run `python -m unittest discover -s tests`. No APK changes or client compatibility claims.
