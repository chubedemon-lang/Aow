"""Regression tests for synthetic movement session ownership.

These tests cover local lifecycle isolation only; they do not define AOW
movement packets, map semantics, or client compatibility.
"""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_movement import MovementError, Position
from server.synthetic_session_movement import SessionMovement


class SameMapReentryTests(unittest.TestCase):
    @staticmethod
    def _in_map(player_id, map_id):
        session = SyntheticSession()
        session.authenticate()
        session.select_character(player_id)
        session.join_map(map_id)
        return session

    def test_leave_and_reenter_same_map_revokes_previous_actor(self):
        session = self._in_map("player_1", "map_1")
        movement = SessionMovement()
        old_actor = movement.spawn(session, Position(0, 0), 5)

        session.leave_map()
        session.join_map("map_1")

        with self.assertRaises(MovementError):
            movement.move(session, 1, Position(1, 0))

        self.assertTrue(old_actor.closed)
        self.assertIsNone(movement.actor)

        new_actor = movement.spawn(session, Position(10, 10), 5)
        self.assertIsNot(new_actor, old_actor)
        self.assertEqual(
            movement.move(session, 1, Position(11, 10)),
            Position(11, 10),
        )

    def test_foreign_sync_revokes_stale_actor_before_rebinding(self):
        owner = self._in_map("player_1", "map_1")
        foreign = self._in_map("player_2", "map_1")
        movement = SessionMovement()
        old_actor = movement.spawn(owner, Position(0, 0), 5)

        self.assertIsNone(movement.sync(foreign))
        self.assertTrue(old_actor.closed)
        self.assertIsNone(movement.actor)

        new_actor = movement.spawn(foreign, Position(20, 20), 5)
        self.assertIsNot(new_actor, old_actor)
        self.assertEqual(
            movement.move(foreign, 1, Position(21, 20)),
            Position(21, 20),
        )
        with self.assertRaises(MovementError):
            movement.move(owner, 1, Position(1, 0))


if __name__ == "__main__":
    unittest.main()
