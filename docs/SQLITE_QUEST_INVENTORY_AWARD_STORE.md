# Synthetic SQLite quest inventory awards

`server/sqlite_quest_inventory_award_store.py` records exactly-once synthetic
item awards after trusted server code has validated quest completion. It is
not an AOW quest contract, reward catalog, packet schema, or APK compatibility
claim.

## Replay and integrity boundary

- A request ID is bound to the character, quest, item, quantity and expected
  inventory revision.
- The award receipt and inventory mutation commit in one SQLite transaction.
- Exact retries return the original award snapshot, even after later inventory
  changes.
- Replay validates the stored character, expected revision and result revision.
- The result snapshot is decoded by the strict inventory receipt validator;
  duplicate JSON keys, non-finite values, boolean/coercible integer fields,
  invalid item rows, non-canonical item order, and identity/revision mismatch
  are rejected as receipt corruption.
- A second request for the same character/quest/item is rejected.

The trusted caller must validate quest completion and authorize character
ownership before invoking this store. Never expose arbitrary reward grants as
a public route or accept untrusted client-supplied reward quantities.

Quest IDs, item IDs, quantities and award semantics here are synthetic
configuration. Do not substitute them for original AOW values without
authorized evidence.

## Tests

Run the focused tests and full suite:

```sh
python -m unittest discover -s tests -p 'test_sqlite_quest_inventory_award_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK, native binary, endpoint, credentials, proprietary assets, packet
captures or live player data belong in this public repository.
