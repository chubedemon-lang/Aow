# Synthetic map occupancy

MapOccupancy is an in-process test/domain primitive backed by the synthetic
SessionRegistry. It is not an AOW map, room, matchmaking, or movement protocol.

## Concurrency boundary

One re-entrant lock protects the complete local admission sequence:

1. Validate the session phase and map identifier.
2. Reconcile stale occupancy entries.
3. Check the per-map capacity.
4. Advance the session into the map.
5. Publish membership and a new local join epoch.

Leave, disconnect, prune, membership reads, epoch reads, and close-all use the
same lock. Concurrent callers using the same MapOccupancy instance therefore
observe a serialized capacity decision; two simultaneous joins cannot both
claim the final slot.

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

The concurrency regression deliberately widens the check-to-transition window
and verifies that exactly one of twelve contenders obtains a map with capacity
one. All identifiers and map values are synthetic. No AOW packet, map ID,
coordinate, room capacity, or APK behavior is inferred.
