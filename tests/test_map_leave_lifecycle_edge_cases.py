"""Edge-case tests for local map leave and connection reuse.

No APK transport or protocol behavior is inferred by these tests.
"""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_map_movement_registry import MapMovementRegistry
from server.synthetic_movement import MovementError, Position
from server.synthetic_session_registry import SessionRegistry


class MapLeaveLifecycleEdgeTests(unittest.TestCase):
    def setUp(self):
        self.sessions = SessionRegistry()
        self.maps = MapOccupancy(self.sessions, capacity_per_map=1)
        self.movement = MapMovementRegistry(self.maps)
        self.sessions.open("conn")
        self.sessions.authenticate("conn", "account")
        self.sessions.select_character("conn", "character")
        self.maps.join("conn", 10)
        self.movement.spawn("conn", Position(0, 0), 2)

    def test_leave_after_external_map_leave_rejects_and_prune_closes_actor(self):
        old = self.movement._actors["conn"]
        self.maps.leave("conn")
        with self.assertRaises(MovementError):
            self.movement.leave_map("conn")
        self.movement.prune()
        self.assertTrue(old.closed)
        self.assertNotIn("conn", self.movement._actors)

    def test_leave_then_join_other_map_requires_new_spawn(self):
        old = self.movement._actors["conn"]
        self.movement.leave_map("conn")
        self.maps.join("conn", 11)
        self.assertTrue(old.closed)
        self.assertIsNone(self.movement.position("conn"))
        with self.assertRaises(MovementError):
            self.movement.move("conn", 0, Position(1, 0))
        self.movement.spawn("conn", Position(5, 5), 2)
        self.assertEqual(self.movement.position("conn"), Position(5, 5))

    def test_disconnect_after_leave_removes_session(self):
        self.movement.leave_map("conn")
        self.assertTrue(self.movement.disconnect("conn"))
        self.assertEqual(self.sessions.active_count, 0)
        self.assertIsNone(self.maps.join_epoch("conn"))

    def test_reused_connection_cannot_move_old_actor_after_external_close(self):
        old = self.movement._actors["conn"]
        self.sessions.close("conn")
        self.sessions.open("conn")
        self.sessions.authenticate("conn", "other-account")
        self.sessions.select_character("conn", "other-character")
        self.maps.join("conn", 10)
        with self.assertRaises(MovementError):
            self.movement.move("conn", 0, Position(1, 0))
        self.movement.spawn("conn", Position(4, 4), 2)
        self.assertTrue(old.closed)
        self.assertEqual(self.movement.position("conn"), Position(4, 4))


if __name__ == "__main__":
    unittest.main()
