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

Receipt replay is fail-closed: stored JSON is size-bounded, duplicate keys and
non-finite numbers are rejected, the top-level/battle/event schemas are exact,
and fighter, turn, revision and winner invariants are rechecked. The decoded
receipt must also match the original battle, owner, actor and expected revision.
A corrupt receipt raises CombatStoreError rather than returning a partial or
misattributed result.

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

## Strict persisted snapshot decoding — 2026-11-14

The authorized combat facade now validates persisted SQLite rows without lossy
`int()` or `str()` coercion before returning a battle snapshot. Numeric
storage values must be actual integers within the synthetic fighter/turn
bounds; REAL and BLOB values are rejected. Revision must equal the battle
turn. The persisted winner column is checked against the terminal battle
state: a non-terminal battle must have two living fighters and no winner, while
a terminal battle must have exactly one defeated fighter and the living winner
must be the next actor.

Regression tests cover fractional numeric values, a BLOB in a numeric field,
revision/turn mismatch, a valid terminal snapshot, and mismatched winner
metadata. This is synthetic persistence validation only; it does not define
AOW combat fields, damage rules, message schemas, or wire compatibility.


## Canonical in-memory turn-state validation — 2026-11-16

The synthetic `Battle` value object validates the turn counter as an
exact built-in integer before any terminal-state comparison, and validates
`next_actor` as an exact built-in integer before membership/equality checks.
Boolean values, floats and integer subclasses are rejected. This prevents a
non-canonical snapshot such as `next_actor=True` from comparing equal to
fighter ID `1`, being accepted by the pure combat model, and then changing
type when SQLite persists it.

Regression tests exercise boolean, float and hostile integer-subclass actor
values, plus a hostile integer-subclass turn counter. This is synthetic domain
validation only; it does not define AOW combat rules or packet fields.


## Canonical fighter-reference validation — 2026-11-16

The in-memory `Battle` value object now requires both participants to be
exact built-in `Fighter` instances before reading any participant fields.
Arbitrary objects and `Fighter` subclasses are rejected, preventing custom
attribute-access hooks from running during participant-ID comparisons.

Regression coverage includes a hostile `Fighter` subclass and non-`Fighter`
objects in both participant positions. This is synthetic domain validation
only; it does not define AOW combat entities, packet fields, or wire
compatibility.
