"""Concurrent map-capacity admission tests; synthetic domain only."""
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_session_registry import RegistryError, SessionRegistry
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

    def test_verified_transfer_cannot_split_map_admission(self):
        registry = SessionRegistry(capacity=1)
        maps = MapOccupancy(registry, capacity_per_map=1)
        session = registry.open("old")
        registry.authenticate("old", "account")
        registry.select_character("old", "hero")

        join_entered = threading.Event()
        release_join = threading.Event()
        transfer_started = threading.Event()
        original_join = session.join_map

        def paused_join(map_id):
            join_entered.set()
            if not release_join.wait(timeout=5):
                raise TimeoutError("test did not release map join")
            return original_join(map_id)

        session.join_map = paused_join

        def transfer():
            transfer_started.set()
            return registry.transfer_connection("old", "new", verified=True)

        with ThreadPoolExecutor(max_workers=2) as pool:
            join_future = pool.submit(maps.join, "old", 77)
            self.assertTrue(join_entered.wait(timeout=5))
            transfer_future = pool.submit(transfer)
            try:
                self.assertTrue(transfer_started.wait(timeout=5))
                time.sleep(0.05)
                self.assertFalse(transfer_future.done())
            finally:
                release_join.set()

            join_future.result(timeout=5)
            with self.assertRaisesRegex(RegistryError, "cannot transfer connection while in map"):
                transfer_future.result(timeout=5)

        self.assertEqual(maps.members(77), frozenset({"old"}))
        self.assertIs(registry.get("old"), session)
        with self.assertRaises(RegistryError):
            registry.get("new")


if __name__ == "__main__":
    unittest.main()
