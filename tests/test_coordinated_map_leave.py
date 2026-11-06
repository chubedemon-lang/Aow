"""Synthetic map-leave lifecycle regression tests (no APK wire assumptions)."""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_map_movement_registry import MapMovementRegistry
from server.synthetic_movement import Position, MovementError
from server.synthetic_session_registry import SessionRegistry
from server.synthetic_session_state import Phase


class CoordinatedLeaveTests(unittest.TestCase):
    def setUp(self):
        self.sessions = SessionRegistry()
        self.maps = MapOccupancy(self.sessions, capacity_per_map=1)
        self.movement = MapMovementRegistry(self.maps)
        for key in ("a", "b"):
            self.sessions.open(key)
            self.sessions.authenticate(key, key)
            self.sessions.select_character(key, key)
        self.maps.join("a", 7)
        self.movement.spawn("a", Position(0, 0), 2)

    def test_leave_releases_capacity_and_closes_actor(self):
        actor = self.movement._actors["a"]
        self.movement.leave_map("a")
        self.assertTrue(actor.closed)
        self.assertIsNone(self.maps.join_epoch("a"))
        self.assertEqual(self.maps.members(7), frozenset())
        self.assertEqual(self.sessions.get("a").snapshot.phase, Phase.CHARACTER_SELECTED)
        self.maps.join("b", 7)

    def test_leave_preserves_session_and_can_rejoin(self):
        old = self.movement._actors["a"]
        self.movement.leave_map("a")
        self.maps.join("a", 7)
        self.assertTrue(old.closed)
        self.assertIsNone(self.movement.position("a"))
        with self.assertRaises(MovementError):
            self.movement.move("a", 1, Position(1, 0))
        self.movement.spawn("a", Position(3, 3), 2)
        self.assertEqual(self.movement.position("a"), Position(3, 3))

    def test_invalid_leave_does_not_close_actor(self):
        actor = self.movement._actors["a"]
        with self.assertRaises(Exception):
            self.movement.leave_map("b")
        self.assertFalse(actor.closed)
        self.assertEqual(self.maps.members(7), frozenset({"a"}))

    def test_double_leave_rejected_without_session_close(self):
        self.movement.leave_map("a")
        with self.assertRaises(Exception):
            self.movement.leave_map("a")
        self.assertEqual(self.sessions.active_count, 2)


if __name__ == "__main__":
    unittest.main()
