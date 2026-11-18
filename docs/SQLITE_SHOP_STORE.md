# Durable synthetic SQLite shop

`server/sqlite_shop_store.py` adds an atomic shop-purchase primitive over the
existing synthetic SQLite player-state and inventory schemas. It is **not**
an AOW item catalog, price list, economy rule, shop packet contract, or proof
of APK compatibility.

## Transaction contract

A new purchase runs under one `BEGIN IMMEDIATE` transaction and:

1. Checks a durable request receipt first.
2. Validates the current server-defined synthetic offer.
3. Checks expected player and inventory revisions.
4. Verifies the player has enough synthetic currency.
5. Verifies the item stack and inventory slot limits.
6. Debits player currency and grants the item.
7. Advances both revisions and writes the existing player/inventory audit rows.
8. Writes the shop receipt and commits all changes together.

A failure at any stage rolls back both the currency debit and item grant. An
identical retry returns the original committed player and inventory snapshots,
even after later mutations or catalog repricing/removal. Reusing the request
ID with different character, revisions, offer ID or quantity is rejected.

Before an idempotent replay is returned, the stored result JSON is validated
for duplicate keys, non-finite values, exact field shapes, integer bounds,
character/offer/quantity identity, and player/inventory revision columns. The
nested inventory snapshot uses the same strict decoder as inventory receipts.
Corrupted receipts fail closed instead of being coerced into a response.

The shop receipt and the two existing mutation ledgers are written in the same
SQLite transaction. Internal ledger request IDs are namespaced by a SHA-256
digest of the shop request ID so the raw caller ID is not reused in either
underlying ledger.

Before a new purchase mutates state, the live player row and inventory header
and item rows are decoded with the same strict snapshot validators used by the
standalone stores. REAL values are not truncated to integers and BLOB item IDs
are not converted to Python string representations. Corrupt persisted state
fails closed without a debit, item grant, revision change, or receipt.

## Read-only integrity audit

`SqliteShopStore.verify_integrity()` verifies every purchase receipt against the exact reserved `shop-` player-state and inventory mutations. It checks canonical request/result payloads, matching character and revision identities, currency debit, item grant payload, and matching result snapshots. It also rejects orphaned reserved mutations. The domain audit runs this check only when a shop receipt or reserved shop mutation is present and requires the complete dependent schemas. The audit never repairs records.

## Boundaries and deployment

- Offer IDs, item IDs, prices, currency limits and purchase quantity limits
  are synthetic server configuration, not extracted AOW values.
- Authenticate the account and authorize ownership of the character before
  calling this store. Do not expose caller-selected character IDs or arbitrary
  grants through public routes.
- Keep the SQLite database private; do not commit database files or live
  player data.
- This store initializes/reuses `SqlitePlayerStateStore` and
  `SqliteInventoryStore` schemas and expects their schema to remain compatible.
- The module is a persistence primitive, not an HTTP route, payment service,
  verified client protocol adapter, or production deployment bundle.

## Tests

Focused regression tests cover atomic debit/grant, stale revisions,
insufficient funds, stack and slot limits, idempotent retries, catalog changes,
reopen persistence, rollback on receipt-write failure, request conflicts,
player isolation, concurrent identical requests, and rejection of corrupted
REAL/BLOB player or inventory storage values before any purchase mutation.

Run:

```sh
python -m unittest discover -s tests -p 'test_sqlite_shop_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK, native library, proprietary assets, credentials, private packet capture
or live player data belongs in this public repository.
