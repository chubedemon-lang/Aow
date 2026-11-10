# Synthetic authorized character lifecycle

**This is not the AOW APK character-initialization or character-selection protocol.**
It is a local domain service that exercises the account/session/character
ownership boundary without inventing AOW wire messages or game rules.

## Operations

The module server/sqlite_authorized_character_service.py provides:

- create(token, name): resolve a durable synthetic account session, verify
  the account exists, create one character with a validated display name,
  a configured synthetic default map ID and origin coordinates (0, 0), then
  create its zero-balance wallet in the same BEGIN IMMEDIATE transaction.
- create_with_initial_state(token, name, level=1, experience=0): atomically create the character and zero-balance wallet, then create a synthetic player snapshot and an unplaced map-position snapshot on the same SQLite transaction. A later authorized map.enter() performs the first synthetic map transition.
- list_for_account(token): list only the authenticated account's characters.
- get(token, character_id): read only a character owned by the authenticated
  account. Unknown and foreign IDs share the same SessionError.

The schema is checked before the session store creates tables. It requires
characters.account_id and wallets.character_id to be unique, plus foreign
keys from characters to accounts and wallets to characters. This enforces the
current synthetic one-character-per-account model and one-wallet-per-character
invariant. Creation and wallet initialization roll back together on failure. The optional create_with_initial_state operation additionally rolls back the character, wallet, player snapshot and unplaced map snapshot as one unit.

## Scope limits

- Names, test_map, origin coordinates, level 1, zero experience/currency and an unplaced map snapshot are synthetic defaults, not recovered AOW rules. The character row's string map_id placeholder is not mapped to the integer map-position ID domain.
- The current schema supports one character per account; character slots,
  deletion, rename, starter inventory and AOW player-init fields are unknown.
- This service has no HTTP route and does not implement APK login, handshake,
  transport framing, message IDs, character-selection packets or compatibility.
- Session tokens must be issued only after trusted authentication. The optional
  local account-auth service and its username limiter remain synthetic.
- Do not expose the localhost mock or connect the original APK until the real
  transport/login/character contract is independently verified.

## Tests

Run: python -m unittest discover -s tests -p 'test_sqlite_authorized_character_service.py' -v
