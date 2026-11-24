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
- The linked inventory mutation uses the exact reserved ID shape
  `quest-` plus 64 lowercase hexadecimal characters. The public inventory
  mutation API rejects that exact shape; ordinary IDs that only start with
  `quest-` are not considered quest receipts by this audit.

The trusted caller must validate quest completion and authorize character
ownership before invoking this store. The quest store alone may write the
reserved inventory mutation ID shape through the inventory store's internal
entry point; arbitrary inventory callers cannot claim that namespace. Never expose arbitrary reward grants as
a public route or accept untrusted client-supplied reward quantities.

Quest IDs, item IDs, quantities and award semantics here are synthetic
configuration. Do not substitute them for original AOW values without
authorized evidence.

## Identifier input boundary

The `request_id` and `item_id` parameters accept exact built-in
strings only. String subclasses are rejected before truthiness, length,
whitespace, encoding, or regular-expression operations can invoke caller-defined
behavior. This matches the inventory store's character/item/request identifier
boundary. The restriction is an input-safety rule for this synthetic persistence
primitive; it does not define AOW item identifiers or quest semantics.

## Tests

Run the focused tests and full suite:

```sh
python -m unittest discover -s tests -p 'test_sqlite_quest_inventory_award_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK, native binary, endpoint, credentials, proprietary assets, packet
captures or live player data belong in this public repository.

## Schema bootstrap and migration boundary

Construction validates the durable receipt schema inside one `BEGIN IMMEDIATE`
transaction. An existing `quest_inventory_awards` object must be a table with
the exact declared column names, SQLite affinities, nullability and primary-key
shape expected by this version. The `(character_id, quest_id, item_id)`
uniqueness constraint and the named `(character_id, quest_id)` lookup index
are also verified; unexpected foreign keys, views, conflicting index names,
or missing uniqueness constraints are rejected.

A valid legacy table may be missing only the non-unique lookup index; the
constructor creates that index and verifies it before commit. Any failed
validation rolls back DDL created by the constructor. It does not rewrite,
repair, or guess a migration for an incompatible existing table. Back up the
database and perform an explicit reviewed migration before upgrading such a
schema.

These checks protect the local synthetic persistence contract only. They do
not establish AOW quest IDs, item IDs, reward semantics, or packet behavior.
