# Synthetic local server foundation

This minimal Python 3.11+ stdlib-only prototype tests account/character persistence and movement. **It is NOT compatible with the AOW APK**: HTTP JSON endpoints, data models, map ID and coordinates are deliberately invented test fixtures, not reverse-engineered findings.

Run tests: `python -m unittest discover -s tests -p 'test_server_mock.py' -v`

Run server: `python -m server.mock --db aow_mock.sqlite3 --port 8765`

It binds only to `127.0.0.1`. Local test endpoints:
- `GET /health`
- `POST /characters` JSON `{"username":"alice","name":"hero"}`
- `GET /characters/1`
- `POST /characters/1/move` JSON `{"x":25,"y":-10}`

This is not production-ready: no authentication, TLS, rate limiting, network compatibility, anti-cheat, world simulation, or client protocol. Do not expose it publicly. Do not place personal data or proprietary client assets in this repository.

Before implementing the real transport adapter, obtain authorized, redacted evidence of the APK's wire protocol. Keep this synthetic interface separate from any verified protocol implementation.

## Inventory domain (synthetic only)

The `Domain` now supports:

- `list_inventory(character_id)`: returns stable, alphabetically sorted `{item_id, quantity}` records.
- `change_inventory(character_id, item_id, delta)`: positive amounts grant stock, negative amounts consume it, and zero remaining quantity removes the row.
- Inventory edits use `BEGIN IMMEDIATE` SQLite transactions to serialize concurrent changes, reject insufficient stock, and prevent 32-bit quantity overflow.
- Item IDs are *test placeholders*, not IDs discovered from the original APK. There is no item catalog, item metadata, gameplay validation, ownership authorization, or original protocol mapping yet.

Tests also cover database reopen/persistence, invalid input, failed consumption, and concurrent increments.

**Important:** Inventory is currently exposed through Python domain methods only, **not** HTTP routes or the APK's transport. Do not expose this mock HTTP service to the internet; it has no authentication or authorization. A verified protocol adapter must be designed before integrating a real client.

## Synthetic wallet and shop domain

- `credit_wallet(character_id, amount)`: operator/test-only wallet funding, integer overflow guarded.
- `set_shop_item(item_id, price, enabled)`: operator-only synthetic catalog management.
- `buy_item(character_id, item_id, count)`: SQLite `BEGIN IMMEDIATE` transaction debits the wallet and grants stock together. Failed purchases roll back completely.
- Unit tests cover persistence, insufficient funds, disabled products, invalid requests and concurrent purchases without overspending.

These methods are intentionally **not exposed as HTTP routes**. No client-supplied price or arbitrary wallet-credit request is accepted. Catalog items, currency and protocol are invented local test fixtures and **not AOW game data**. Real integration requires verified item IDs, economy rules, server-side authorization, session ownership and client message schemas.

## Strict synthetic HTTP request parsing

The localhost-only mock now accepts POST bodies only when they have one `Content-Type: application/json`, one decimal `Content-Length` within the 4 KiB limit, UTF-8 encoding, and a JSON object root. It rejects transfer-encoding, compressed bodies, duplicate request headers, duplicate JSON keys (including nested objects), non-finite numbers, invalid UTF-8 and truncated bodies. These are generic HTTP input-safety rules for the synthetic test API; they are not evidence about AOW's transport or serialization.
