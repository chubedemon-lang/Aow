# Synthetic map occupancy

MapOccupancy is an in-process test/domain primitive backed by the synthetic
SessionRegistry. It is not an AOW map, room, matchmaking, or movement protocol.

## Concurrency boundary

A re-entrant occupancy lock protects local map membership. During admission,
MapOccupancy also holds the SessionRegistry lock until the session transition
and stable-identity membership entry have both been published. This prevents a
verified connection handoff from changing the key between the session
transition and occupancy insertion.

Membership and join epochs are keyed by the stable in-memory Session object,
not by a replaceable connection identifier. The registry maintains a reverse
lookup from each live Session object to its current connection key. A verified
handoff therefore preserves map occupancy and join epoch under the new key.
Closing a session removes the reverse lookup; the next prune discards its stale
occupancy entry.

The admission sequence is:

1. Hold the occupancy lock and the registry's locked-session context.
2. Validate the session phase and map identifier.
3. Reconcile stale occupancy entries.
4. Check the per-map capacity.
5. Advance the session into the map.
6. Publish membership and a new local join epoch.
7. Release the registry lock and then the occupancy lock.

Leave and disconnect also hold the registry lock across the session transition
and membership removal. Membership queries resolve all current connection
keys under one registry snapshot. Concurrent callers using the same
MapOccupancy instance therefore observe a serialized capacity decision; two
simultaneous joins cannot both claim the final slot, and an in-map handoff does
not orphan an occupant.

The lock is process-local and instance-local. It does not coordinate multiple
MapOccupancy instances, worker processes, or hosts. A future multi-process
server must move capacity admission and membership into a durable transactional
store with an explicit schema and uniqueness/locking contract. Do not treat
this helper as production matchmaking.

## Validation

Run:

    python -m unittest discover -s tests -p 'test_synthetic_map_occupancy.py' -v
    python -m unittest discover -s tests -p 'test_synthetic_map_occupancy_concurrency.py' -v
    python -m unittest discover -s tests -p 'test_synthetic_map_occupancy_prune.py' -v

The concurrency regressions verify that exactly one of twelve contenders
obtains a map with capacity one, and that a verified handoff during admission
preserves membership and join epoch under the new connection key. All
identifiers and map values are synthetic. No AOW packet, map ID, coordinate,
room capacity, reconnect behavior, or APK behavior is inferred.
