"""Regression: a same-map re-entry is a new synthetic movement epoch.

This tests local lifecycle invalidation only; it does not define AOW map semantics.
"""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_movement import MovementError, Position
from server.synthetic_session_movement import SessionMovement


class SameMapReentryTests(unittest.TestCase):
    def test_leave_and_reenter_same_map_revokes_previous_actor(self):
        session = SyntheticSession()
        session.authenticate()
        session.select_character("player_1")
        session.join_map("map_1")

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


if __name__ == "__main__":
    unittest.main()
