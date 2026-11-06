"""Local-only occupancy reconciliation regression tests (not APK wire fixtures)."""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_session_registry import SessionRegistry


class OccupancyPruneTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.maps = MapOccupancy(self.registry, capacity_per_map=1)
        for key in ("a", "b"):
            self.registry.open(key)
            self.registry.authenticate(key, key)
            self.registry.select_character(key, key)

    def test_direct_session_close_releases_capacity(self):
        self.maps.join("a", 42)
        self.registry.close("a")
        self.assertEqual(self.maps.prune(), 1)
        self.assertFalse(self.maps.members(42))
        self.assertIsNone(self.maps.join_epoch("a"))
        self.maps.join("b", 42)
        self.assertEqual(self.maps.members(42), frozenset({"b"}))

    def test_reused_connection_id_without_map_join_is_pruned(self):
        self.maps.join("a", 42)
        self.registry.close("a")
        self.registry.open("a")
        self.registry.authenticate("a", "new-account")
        self.registry.select_character("a", "new-character")
        self.assertEqual(self.maps.prune(), 1)
        self.assertIsNone(self.maps.join_epoch("a"))
        self.assertEqual(self.registry.get("a").snapshot.map_id, None)

    def test_valid_membership_and_epoch_survive_prune(self):
        self.maps.join("a", 42)
        epoch = self.maps.join_epoch("a")
        self.assertEqual(self.maps.prune(), 0)
        self.assertEqual(self.maps.members(42), frozenset({"a"}))
        self.assertEqual(self.maps.join_epoch("a"), epoch)

    def test_prune_idempotent_after_leave(self):
        self.maps.join("a", 42)
        self.maps.leave("a")
        self.assertEqual(self.maps.prune(), 0)
        self.assertEqual(self.maps.prune(), 0)

    def test_prune_after_close_all_is_safe(self):
        self.maps.join("a", 42)
        self.registry.close_all()
        self.assertEqual(self.maps.prune(), 1)
        self.assertEqual(self.maps.prune(), 0)


if __name__ == "__main__":
    unittest.main()
