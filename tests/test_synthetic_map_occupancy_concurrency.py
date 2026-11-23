"""Concurrent map-capacity admission tests; synthetic domain only."""
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_session_registry import SessionRegistry
from server.synthetic_session_state import Phase


class MapOccupancyConcurrencyTests(unittest.TestCase):
    def test_concurrent_joins_never_exceed_per_map_capacity(self):
        worker_count = 12
        registry = SessionRegistry(capacity=worker_count)
        maps = MapOccupancy(registry, capacity_per_map=1)
        connection_ids = []

        for index in range(worker_count):
            connection_id = "connection-" + str(index)
            session = registry.open(connection_id)
            registry.authenticate(connection_id, "account-" + str(index))
            registry.select_character(connection_id, "character-" + str(index))
            original_join = session.join_map

            # Widen the check-to-transition race window. With no occupancy
            # lock, every worker can pass the capacity check before any worker
            # completes the session transition and membership insertion.
            def delayed_join(map_id, original=original_join):
                time.sleep(0.03)
                return original(map_id)

            session.join_map = delayed_join
            connection_ids.append(connection_id)

        barrier = threading.Barrier(worker_count)

        def attempt(connection_id):
            barrier.wait(timeout=5)
            try:
                maps.join(connection_id, 77)
                return connection_id
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            winners = list(pool.map(attempt, connection_ids))

        successful = [connection_id for connection_id in winners if connection_id]
        self.assertEqual(len(successful), 1)
        self.assertEqual(maps.members(77), frozenset(successful))
        self.assertEqual(
            sum(
                registry.get(connection_id).snapshot.phase is Phase.IN_MAP
                for connection_id in connection_ids
            ),
            1,
        )
        self.assertEqual(
            sum(maps.join_epoch(connection_id) is not None
                for connection_id in connection_ids),
            1,
        )


if __name__ == "__main__":
    unittest.main()
