"""Concurrency regressions for synthetic session and player lease fixtures."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from server.synthetic_connection_manager import SyntheticConnectionManager
from server.synthetic_player_lease import PlayerLeaseError, PlayerLeaseRegistry
from server.synthetic_session import SessionError


def authenticate(manager, connection_id):
    gate = manager.open(connection_id)
    gate.challenge(b"nonce-123456")
    gate.acknowledge(b"nonce-123456")
    gate.authenticate("account-" + connection_id)
    return gate


class SyntheticConcurrencyTests(unittest.TestCase):
    def test_registry_allows_only_one_concurrent_owner(self):
        registry = PlayerLeaseRegistry()
        barrier = Barrier(2)

        def claim(connection_id):
            barrier.wait(timeout=5)
            try:
                registry.acquire(connection_id, "shared-player")
                return connection_id
            except PlayerLeaseError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            winners = list(pool.map(claim, ("connection-a", "connection-b")))

        winner = next(value for value in winners if value is not None)
        self.assertEqual(registry.owner_of("shared-player"), winner)
        self.assertEqual(sum(value is not None for value in winners), 1)
        self.assertEqual(registry.active_count, 1)

    def test_manager_allows_only_one_concurrent_player_selection(self):
        manager = SyntheticConnectionManager()
        authenticate(manager, "connection-a")
        authenticate(manager, "connection-b")
        barrier = Barrier(2)

        def select(connection_id):
            barrier.wait(timeout=5)
            try:
                manager.select_player(connection_id, "shared-player")
                return connection_id
            except PlayerLeaseError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            winners = list(pool.map(select, ("connection-a", "connection-b")))

        winner = next(value for value in winners if value is not None)
        self.assertEqual(manager.leases.owner_of("shared-player"), winner)
        self.assertEqual(sum(value is not None for value in winners), 1)
        self.assertEqual(manager.leases.active_count, 1)

    def test_concurrent_duplicate_open_has_one_winner(self):
        manager = SyntheticConnectionManager()
        barrier = Barrier(2)

        def open_connection():
            barrier.wait(timeout=5)
            try:
                manager.open("same-connection")
                return True
            except SessionError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: open_connection(), range(2)))

        self.assertEqual(outcomes.count(True), 1)
        self.assertEqual(outcomes.count(False), 1)
        self.assertEqual(manager.active_connections, 1)

    def test_concurrent_close_releases_lease_exactly_once(self):
        manager = SyntheticConnectionManager()
        authenticate(manager, "connection-a")
        manager.select_player("connection-a", "player-a")
        barrier = Barrier(2)

        def close_connection():
            barrier.wait(timeout=5)
            return manager.close("connection-a")

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: close_connection(), range(2)))

        self.assertCountEqual(outcomes, [True, False])
        self.assertEqual(manager.active_connections, 0)
        self.assertEqual(manager.leases.active_count, 0)


if __name__ == "__main__":
    unittest.main()
