"""Synthetic map lifecycle regression tests; no AOW wire assumptions."""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_session_registry import SessionRegistry
from server.synthetic_session_state import Phase, SessionError


class MapOccupancyTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.maps = MapOccupancy(self.registry, 1)
        for key in ("a", "b"):
            self.registry.open(key)
            self.registry.authenticate(key, key)
            self.registry.select_character(key, key)

    def test_join_leave_rejoin(self):
        self.maps.join("a", 7)
        self.assertEqual(self.maps.members(7), frozenset({"a"}))
        self.maps.leave("a")
        self.assertEqual(self.maps.members(7), frozenset())
        self.maps.join("b", 7)
        self.assertEqual(self.maps.members(7), frozenset({"b"}))

    def test_capacity_rejection_preserves_state(self):
        self.maps.join("a", 7)
        with self.assertRaises(ValueError):
            self.maps.join("b", 7)
        self.assertEqual(self.registry.get("b").snapshot.phase, Phase.CHARACTER_SELECTED)
        self.assertEqual(self.maps.members(7), frozenset({"a"}))

    def test_invalid_map_does_not_change_session(self):
        for value in (True, -1, 2**31, "7", None):
            with self.assertRaises((SessionError, ValueError)):
                self.maps.join("a", value)
        self.assertEqual(self.registry.get("a").snapshot.phase, Phase.CHARACTER_SELECTED)

    def test_duplicate_join_does_not_change_membership(self):
        self.maps.join("a", 7)
        with self.assertRaises(SessionError):
            self.maps.join("a", 8)
        self.assertEqual(self.maps.members(7), frozenset({"a"}))
        self.assertFalse(self.maps.members(8))

    def test_disconnect_frees_capacity_and_clears_identity(self):
        self.maps.join("a", 7)
        old = self.registry.get("a")
        self.assertTrue(self.maps.disconnect("a"))
        self.assertEqual(old.snapshot.phase, Phase.CLOSED)
        self.assertIsNone(old.snapshot.account_id)
        self.maps.join("b", 7)
        self.assertEqual(self.maps.members(7), frozenset({"b"}))

    def test_isolated_maps_and_close_all(self):
        self.maps.join("a", 7)
        self.maps.join("b", 8)
        self.assertEqual(self.maps.members(7), frozenset({"a"}))
        self.assertEqual(self.maps.members(8), frozenset({"b"}))
        self.maps.close_all()
        self.assertEqual(self.registry.active_count, 0)
        self.assertFalse(self.maps.members(7))
        self.assertFalse(self.maps.members(8))

    def test_constructor_validation(self):
        with self.assertRaises(TypeError):
            MapOccupancy(None)
        for capacity in (0, True, -1, 100001, "3"):
            with self.assertRaises(ValueError):
                MapOccupancy(self.registry, capacity)


if __name__ == "__main__":
    unittest.main()
