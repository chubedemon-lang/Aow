"""Synthetic lease tests only; no AOW APK wire compatibility claim."""
import unittest

from server.synthetic_player_lease import PlayerLeaseError, PlayerLeaseRegistry


class PlayerLeaseTests(unittest.TestCase):
    def test_duplicate_player_rejected_and_released(self):
        registry = PlayerLeaseRegistry()
        registry.acquire("connection-a", "player")
        with self.assertRaises(PlayerLeaseError):
            registry.acquire("connection-b", "player")
        self.assertEqual(registry.owner_of("player"), "connection-a")
        self.assertTrue(registry.release("connection-a"))
        registry.acquire("connection-b", "player")
        self.assertEqual(registry.owner_of("player"), "connection-b")

    def test_connection_cannot_lease_two_players(self):
        registry = PlayerLeaseRegistry()
        registry.acquire("connection", "first")
        with self.assertRaises(PlayerLeaseError):
            registry.acquire("connection", "second")
        self.assertIsNone(registry.owner_of("second"))
        self.assertEqual(registry.active_count, 1)

    def test_capacity_and_idempotent_release(self):
        registry = PlayerLeaseRegistry(1)
        registry.acquire("a", "one")
        with self.assertRaises(PlayerLeaseError):
            registry.acquire("b", "two")
        self.assertEqual(registry.active_count, 1)
        self.assertTrue(registry.release("a"))
        self.assertFalse(registry.release("a"))
        registry.acquire("b", "two")
        self.assertEqual(registry.active_count, 1)

    def test_invalid_identifiers_and_capacity_do_not_mutate(self):
        for capacity in (True, 0, -1, 1000001, "2"):
            with self.subTest(capacity=capacity), self.assertRaises(PlayerLeaseError):
                PlayerLeaseRegistry(capacity)
        registry = PlayerLeaseRegistry()
        for bad in ("", " ", "\u200b", "x\n", "x" * 129, None, True):
            with self.subTest(bad=bad), self.assertRaises(PlayerLeaseError):
                registry.acquire(bad, "player")
            with self.subTest(bad=bad), self.assertRaises(PlayerLeaseError):
                registry.acquire("connection", bad)
        self.assertEqual(registry.active_count, 0)

    def test_independent_connections(self):
        registry = PlayerLeaseRegistry()
        registry.acquire("a", "p1")
        registry.acquire("b", "p2")
        self.assertTrue(registry.release("a"))
        self.assertEqual(registry.owner_of("p2"), "b")
        self.assertEqual(registry.active_count, 1)


if __name__ == "__main__":
    unittest.main()
