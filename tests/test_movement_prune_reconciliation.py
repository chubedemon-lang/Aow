"""Regression tests for local synthetic movement/occupancy reconciliation."""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_map_movement_registry import MapMovementRegistry
from server.synthetic_movement import Position
from server.synthetic_session_registry import SessionRegistry


class MovementPruneReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.sessions = SessionRegistry()
        self.maps = MapOccupancy(self.sessions, capacity_per_map=1)
        self.movement = MapMovementRegistry(self.maps)
        for key in ("a", "b"):
            self.sessions.open(key)
            self.sessions.authenticate(key, key)
            self.sessions.select_character(key, key)
        self.maps.join("a", 1)
        self.movement.spawn("a", Position(0, 0), 2)

    def test_direct_close_prune_cleans_actor_and_membership(self):
        actor = self.movement._actors["a"]
        self.sessions.close("a")
        self.movement.prune()
        self.assertTrue(actor.closed)
        self.assertEqual(self.maps.members(1), frozenset())
        self.assertIsNone(self.maps.join_epoch("a"))
        self.maps.join("b", 1)

    def test_direct_leave_prune_cleans_actor_and_membership(self):
        actor = self.movement._actors["a"]
        self.sessions.get("a").leave_map()
        self.movement.prune()
        self.assertTrue(actor.closed)
        self.assertEqual(self.maps.members(1), frozenset())
        self.maps.join("b", 1)

    def test_live_actor_survives_prune(self):
        actor = self.movement._actors["a"]
        self.movement.prune()
        self.assertIs(self.movement._actors["a"], actor)
        self.assertFalse(actor.closed)
        self.assertEqual(self.maps.members(1), frozenset({"a"}))

    def test_repeated_prune_is_safe(self):
        self.sessions.close("a")
        self.movement.prune()
        self.movement.prune()
        self.assertFalse(self.movement._actors)
        self.assertEqual(self.maps.members(1), frozenset())


if __name__ == "__main__":
    unittest.main()
