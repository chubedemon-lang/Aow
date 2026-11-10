# Synthetic durable combat persistence

This module persists the repository's deterministic local combat rules. It is
not an AOW battle protocol, damage formula, skill system, matchmaking service,
or production anti-cheat implementation.

## Ownership and lifecycle

server/sqlite_authorized_combat_service.py exposes a local Python domain
facade backed by the existing characters(id, account_id) and durable SQLite
session tables.

- A battle is created for one owned character and one synthetic opponent.
- The owned character must be exactly one of the two fighters.
- Reads and mutations require an active durable session for the owning account
  and the same character that created the battle.
- A different character owned by the same account cannot read another
  character's battle.
- Ownership transfer is not supported.

## Atomic turn persistence

Each accepted turn:

1. Starts a SQLite BEGIN IMMEDIATE transaction.
2. Checks battle ownership and the request receipt.
3. Checks the expected battle revision.
4. Applies the existing immutable server.combat.Battle.attack transition.
5. Updates the battle snapshot and stores the resulting event/receipt.
6. Commits the state and receipt together.

An exact retry returns the original snapshot and event, even after later turns.
Reusing a request ID with another payload is rejected. Stale revisions and
invalid turns do not create receipts or mutate the battle.

## Trusted actor boundary

attack(..., actor_id=...) is an internal trusted-domain operation. The
server-side combat coordinator must choose the actor. Do not expose actor_id
as a client-controlled HTTP or packet field; in particular, a client must not
be allowed to request an NPC turn. This repository does not register an HTTP
route for this service.

## Verification

Run:

~~~sh
python -m unittest discover -s tests -p 'test_sqlite_authorized_combat_service.py' -v
python -m unittest discover -s tests -p 'test_combat.py' -v
python -m unittest discover -s tests -v
~~~

The tests cover ownership, expiry/revocation, durable restart, turn order,
terminal battles, optimistic revisions, idempotent replay, concurrent duplicate
requests, and schema fail-closed behavior.

All fighter stats and IDs remain synthetic. No APK packet, combat catalog,
asset, or original-game rule is inferred here.
