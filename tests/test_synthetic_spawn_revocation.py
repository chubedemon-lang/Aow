"""Regression coverage for synthetic movement revocation on rejected spawn."""

import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_movement import SessionMovement
from server.synthetic_movement import MovementError, Position


def in_map():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("player_1")
    session.join_map("map_1")
    return session


class SpawnRevocationTests(unittest.TestCase):
    def test_closed_session_rejected_spawn_revokes_old_actor(self):
        session = in_map()
        movement = SessionMovement()
        old = movement.spawn(session, Position(0, 0), 5)
        session.close()
        with self.assertRaises(MovementError):
            movement.spawn(session, Position(0, 0), 5)
        self.assertTrue(old.closed)
        self.assertIsNone(movement.actor)

    def test_departed_session_rejected_spawn_revokes_old_actor(self):
        session = in_map()
        movement = SessionMovement()
        old = movement.spawn(session, Position(0, 0), 5)
        session.leave_map()
        with self.assertRaises(MovementError):
            movement.spawn(session, Position(0, 0), 5)
        self.assertTrue(old.closed)
        self.assertIsNone(movement.actor)

    def test_cross_session_invalid_spawn_revokes_old_actor(self):
        first = in_map()
        second = SyntheticSession()
        movement = SessionMovement()
        old = movement.spawn(first, Position(0, 0), 5)
        with self.assertRaises(MovementError):
            movement.spawn(second, Position(0, 0), 5)
        self.assertTrue(old.closed)
        self.assertIsNone(movement.actor)


if __name__ == "__main__":
    unittest.main()
