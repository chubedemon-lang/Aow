"""Regression tests for synthetic map reentry and session ownership."""

import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_movement import SessionMovement
from server.synthetic_movement import MovementError, Position


def ready():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("player_1")
    session.join_map("map_1")
    return session


class ReentryTests(unittest.TestCase):
    def test_same_map_reentry_without_intermediate_sync_revokes_actor(self):
        session = ready()
        adapter = SessionMovement()
        old = adapter.spawn(session, Position(0, 0), 5)
        session.leave_map()
        session.join_map("map_1")
        with self.assertRaises(MovementError):
            adapter.move(session, 1, Position(1, 1))
        self.assertTrue(old.closed)
        self.assertIsNone(adapter.actor)
        fresh = adapter.spawn(session, Position(0, 0), 5)
        self.assertIsNot(fresh, old)
        self.assertEqual(adapter.move(session, 0, Position(1, 1)), Position(1, 1))

    def test_same_map_reentry_sync_revokes_actor(self):
        session = ready()
        adapter = SessionMovement()
        old = adapter.spawn(session, Position(0, 0), 5)
        session.leave_map()
        session.join_map("map_1")
        self.assertIsNone(adapter.sync(session))
        self.assertTrue(old.closed)

    def test_different_session_same_map_cannot_reuse_actor(self):
        first, second = ready(), ready()
        adapter = SessionMovement()
        old = adapter.spawn(first, Position(0, 0), 5)
        with self.assertRaises(MovementError):
            adapter.move(second, 1, Position(1, 1))
        self.assertTrue(old.closed)
        self.assertIsNone(adapter.actor)


if __name__ == "__main__":
    unittest.main()
