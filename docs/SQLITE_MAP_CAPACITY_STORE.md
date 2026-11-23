# SQLite map-capacity projection

## Scope

This module adds durable capacity limits and a membership projection for the
repository's synthetic map-position domain. It is not an AOW room, map ID,
matchmaking, reconnect, or movement contract. Map IDs and capacities are
caller-supplied test/server configuration; no original-game value is inferred.

## Schema

- map_capacity_limits stores one positive bounded capacity for each configured
  synthetic map.
- map_capacity_members stores at most one current map membership per character.
  Its character key references map_position_snapshots and cascades on deletion.
- A map_id index supports bounded occupancy counts.

Construction requires an idle SQLite connection and an initialized
map_position_snapshots table. The store verifies its column signatures, foreign
key, index, and CHECK-constraint presence. The connection remains caller-owned.

## Operations

- configure_map(map_id, capacity) persists a limit and seeds characters whose
  current position is already on that map. A limit below current occupancy is
  rejected without changing the previous configuration.
- reconcile(character_id, map_id) requires the supplied map ID to exactly match
  the durable position snapshot. It inserts, moves, or removes the membership
  projection. An unconfigured map is not capacity-managed.
- members(map_id) and capacity(map_id) expose the current synthetic projection.
- verify_integrity() checks SQLite quick_check, foreign keys, membership/
  position agreement, missing memberships on configured maps, memberships on
  unconfigured maps, and capacity overruns. It is diagnostic and never repairs state.

## Transaction and multi-connection behavior

Standalone writes use BEGIN IMMEDIATE. When called inside an existing caller
transaction, each operation uses a savepoint and leaves outer commit/rollback
ownership with the caller. Independent SQLite connections therefore serialize
capacity admission through the database write reservation, rather than relying
on a process-local Python lock.

SqliteAuthorizedMapService owns the composition boundary: enter/move/leave first
mutate the durable position, then reconcile capacity using the current stored
snapshot, all inside the same authorized_character_transaction. If capacity
admission fails, the position mutation and its idempotency receipt roll back
with it. The service accepts an optional map_capacities dictionary at startup;
configure_map_capacity is an administrative local method and is not exposed as
a player route. Every worker must use the same SQLite database and configured
capacity rows.

The service reconciles from the current position rather than the returned
mutation receipt. This is important because an exact idempotent retry can return
an old receipt after later transitions; replaying that receipt must not
resurrect a character's previous occupancy.

## Validation

Run:

    python -m unittest discover -s tests -p 'test_sqlite_map_capacity_store.py' -v
    python -m unittest discover -s tests -p 'test_sqlite_authorized_map_capacity_service.py' -v

The tests use temporary SQLite databases, synthetic character IDs, and
independent connections. They do not contact any game endpoint.

## Explicit non-goals

This projection does not establish AOW map IDs, room capacity, coordinates,
spawn rules, map transfer behavior, wire messages, packet framing, handshake,
login, or APK compatibility. It is a durable domain primitive only. A future
wire adapter must remain disabled until the original APK contract is supported
by authorized, provenance-reviewed evidence and end-to-end tests.
