"""Regression tests for synthetic world position ownership."""
import unittest

from server.movement_validation import Position, MovementError
from server.player_presence import PresenceRegistry, PresenceError
from server.session_state import Session
from server.world_position import WorldPositionTracker


class WorldPositionTests(unittest.TestCase):
    def setUp(self):
        self.registry = PresenceRegistry()
        self.tracker = WorldPositionTracker(self.registry, max_speed=5)
        self.session = Session("s1")
        self.session.authenticate("p1")
        self.registry.bind(self.session)
        self.session.enter_world()
        self.registry.enter_map(self.session, "map1")

    def test_spawn_and_move(self):
        self.tracker.spawn(self.session, Position(0, 0), 10)
        moved = self.tracker.move(self.session, Position(3, 4), 11)
        self.assertEqual(moved.position, Position(3, 4))

    def test_speed_violation_does_not_mutate(self):
        original = self.tracker.spawn(self.session, Position(0, 0), 10)
        with self.assertRaises(MovementError):
            self.tracker.move(self.session, Position(100, 0), 11)
        self.assertEqual(self.tracker.get("p1"), original)

    def test_timestamp_replay_rejected(self):
        self.tracker.spawn(self.session, Position(0, 0), 10)
        for timestamp in (10, 9, float("nan"), -1, True):
            with self.assertRaises(MovementError):
                self.tracker.move(self.session, Position(0, 0), timestamp)

    def test_duplicate_spawn_rejected(self):
        self.tracker.spawn(self.session, Position(0, 0), 1)
        with self.assertRaises(PresenceError):
            self.tracker.spawn(self.session, Position(0, 0), 2)

    def test_wrong_session_cannot_move_or_despawn(self):
        other = Session("s2")
        other.authenticate("p1")
        other.enter_world()
        self.tracker.spawn(self.session, Position(0, 0), 1)
        with self.assertRaises(PresenceError):
            self.tracker.move(other, Position(0, 0), 2)
        with self.assertRaises(PresenceError):
            self.tracker.despawn(other)

    def test_map_change_requires_despawn_and_respawn(self):
        self.tracker.spawn(self.session, Position(0, 0), 1)
        self.registry.leave_map(self.session)
        self.registry.enter_map(self.session, "map2")
        with self.assertRaises(PresenceError):
            self.tracker.move(self.session, Position(1, 0), 2)
        self.tracker.despawn(self.session)
        self.tracker.spawn(self.session, Position(5, 5), 3)
        self.assertEqual(self.tracker.get("p1").map_id, "map2")

    def test_unbound_player_rejected(self):
        self.registry.leave_map(self.session)
        with self.assertRaises(PresenceError):
            self.tracker.spawn(self.session, Position(0, 0), 1)


if __name__ == "__main__":
    unittest.main()
