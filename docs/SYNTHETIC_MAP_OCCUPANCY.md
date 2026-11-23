# Synthetic map occupancy

MapOccupancy is an in-process test/domain primitive backed by the synthetic
SessionRegistry. It is not an AOW map, room, matchmaking, or movement protocol.

## Concurrency boundary

A re-entrant occupancy lock protects local map membership. During admission,
MapOccupancy also holds the SessionRegistry lock until the session transition,
membership entry, and join epoch have all been published. This prevents a
verified connection handoff from moving the registry key between the session
transition and occupancy insertion.

A verified connection transfer is rejected while a session is IN_MAP because
this local occupancy index is keyed by the current connection identifier.
Callers must leave the synthetic map before transferring the connection.
This is a conservative in-memory invariant, not a claim about AOW reconnect
semantics.

The admission sequence is:

1. Hold the occupancy lock and the registry's locked-session context.
2. Validate the session phase and map identifier.
3. Reconcile stale occupancy entries.
4. Check the per-map capacity.
5. Advance the session into the map.
6. Publish membership and a new local join epoch.
7. Release the registry lock and then the occupancy lock.

Leave, disconnect, prune, membership reads, epoch reads, and close-all use the
occupancy lock. Concurrent callers using the same MapOccupancy instance
therefore observe a serialized capacity decision; two simultaneous joins
cannot both claim the final slot.

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
obtains a map with capacity one, and that a verified connection transfer cannot
interleave with map admission and orphan the occupancy key. All identifiers
and map values are synthetic. No AOW packet, map ID, coordinate, room capacity,
reconnect behavior, or APK behavior is inferred.
