# Quest-to-inventory award boundary

This module is a synthetic server-domain persistence boundary, not an AOW
quest contract or packet implementation.

## Transaction

`SqliteAuthorizedQuestInventoryAwardService.grant_once` holds one
`BEGIN IMMEDIATE` transaction across:

1. durable session resolution;
2. `characters.account_id` ownership authorization;
3. unique per-character / quest / item award lookup;
4. inventory revision-checked item grant;
5. durable quest-award receipt insertion.

The inventory mutation receipt and quest award receipt commit together. A
failed inventory mutation rolls back the award record. An exact retry returns
the original inventory snapshot; a second request for the same character,
quest and item is rejected.

## Trust boundary

The caller must validate quest completion in trusted server-side quest logic
before invoking this service. The service deliberately does not accept a
client-supplied `completed=true` flag and is not registered as an HTTP route.
Session issuance must remain behind trusted account authentication.

## Still missing

- AOW quest completion, progression, item IDs and reward rules.
- A verified APK quest/reward wire contract.
- An authenticated HTTP adapter backed by verified login/session semantics.
- End-to-end tests using the unchanged APK and authorized redacted fixtures.

All item IDs, quest IDs and quantities in current tests are synthetic.
