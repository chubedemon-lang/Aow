"""Integration tests for local-only map movement; not APK protocol fixtures."""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_map_movement_registry import MapMovementRegistry
from server.synthetic_movement import MovementError, Position
from server.synthetic_session_registry import SessionRegistry


class MapMovementRegistryTests(unittest.TestCase):
    def setUp(self):
        self.sessions = SessionRegistry()
        self.maps = MapOccupancy(self.sessions)
        self.movement = MapMovementRegistry(self.maps)
        for key in ("a", "b"):
            self.sessions.open(key)
            self.sessions.authenticate(key, key)
            self.sessions.select_character(key, key)
        self.maps.join("a", 1)

    def test_spawn_move_and_replay_rejected(self):
        self.movement.spawn("a", Position(0, 0), 5)
        self.assertEqual(self.movement.move("a", 1, Position(3, 4)), Position(3, 4))
        with self.assertRaises(MovementError):
            self.movement.move("a", 1, Position(4, 4))
        self.assertEqual(self.movement.position("a"), Position(3, 4))

    def test_not_in_map_cannot_spawn(self):
        with self.assertRaises(MovementError):
            self.movement.spawn("b", Position(0, 0), 1)

    def test_duplicate_spawn_is_atomic(self):
        self.movement.spawn("a", Position(0, 0), 5)
        with self.assertRaises(MovementError):
            self.movement.spawn("a", Position(99, 99), 5)
        self.assertEqual(self.movement.position("a"), Position(0, 0))

    def test_leave_and_rejoin_requires_new_spawn(self):
        self.movement.spawn("a", Position(0, 0), 5)
        self.maps.leave("a")
        with self.assertRaises(MovementError):
            self.movement.move("a", 1, Position(1, 0))
        self.maps.join("a", 2)
        with self.assertRaises(MovementError):
            self.movement.move("a", 1, Position(1, 0))
        self.movement.spawn("a", Position(7, 7), 5)
        self.assertEqual(self.movement.position("a"), Position(7, 7))

    def test_disconnect_prune_and_reuse(self):
        self.movement.spawn("a", Position(0, 0), 5)
        self.maps.disconnect("a")
        self.movement.prune()
        self.assertFalse(self.movement._actors)
        self.sessions.open("a")
        self.sessions.authenticate("a", "new-account")
        self.sessions.select_character("a", "new-character")
        self.maps.join("a", 1)
        self.movement.spawn("a", Position(2, 2), 1)
        self.assertEqual(self.movement.position("a"), Position(2, 2))

    def test_invalid_step_does_not_change_position(self):
        self.movement.spawn("a", Position(0, 0), 2)
        with self.assertRaises(MovementError):
            self.movement.move("a", 1, Position(3, 0))
        self.assertEqual(self.movement.position("a"), Position(0, 0))

    def test_constructor_validation(self):
        with self.assertRaises(TypeError):
            MapMovementRegistry(None)


if __name__ == "__main__":
    unittest.main()
