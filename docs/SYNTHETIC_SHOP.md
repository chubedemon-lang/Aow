# Synthetic shop transactions

`server/synthetic_shop.py` implements an **offline-only** in-memory shop and wallet, backed by `InventoryLedger`. Offers have synthetic IDs and positive integer prices. Purchases enforce quantity limits, balance checks and inventory constraints; a rejected inventory grant does not debit the wallet. `tests/test_synthetic_shop.py` covers success, rejection, bounds and player isolation.

Run locally: `python -m unittest discover -s tests -v`.

**Not AOW-derived:** offer IDs, prices, currency, item IDs, shop UI, packet framing and messages are invented test data. This is not a real payment system. No persistence, concurrency control, idempotency keys, authenticated session binding, crash recovery, database transactions or verified APK compatibility. Do not expose it to network clients until those properties and the authorized offline APK protocol are established.
