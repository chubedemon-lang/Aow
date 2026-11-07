"""Regression tests for atomic synthetic actor spawn and map transitions.

No assertions about the original AOW APK or its wire protocol.
"""
import unittest

from server.synthetic_movement import MovementError, Position
from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_movement import SessionMovement


def in_map(map_id="map_a"):
    session = SyntheticSession()
    session.authenticate()
    session.select_character("player_a")
    session.join_map(map_id)
    return session


class SpawnAtomicityTests(unittest.TestCase):
    def test_duplicate_spawn_keeps_existing_actor(self):
        session = in_map()
        adapter = SessionMovement()
        actor = adapter.spawn(session, Position(0, 0), 5)
        with self.assertRaises(MovementError):
            adapter.spawn(session, Position(10, 10), 5)
        self.assertIs(adapter.actor, actor)
        self.assertFalse(actor.closed)
        adapter.move(session, 1, Position(1, 0))

    def test_new_map_requires_fresh_spawn(self):
        session = in_map()
        adapter = SessionMovement()
        old = adapter.spawn(session, Position(0, 0), 5)
        session.leave_map()
        session.join_map("map_b")
        with self.assertRaises(MovementError):
            adapter.move(session, 1, Position(1, 0))
        self.assertTrue(old.closed)
        self.assertIsNone(adapter.actor)
        new = adapter.spawn(session, Position(0, 0), 5)
        self.assertIsNot(new, old)
        adapter.move(session, 1, Position(1, 0))

    def test_reentry_same_map_requires_fresh_spawn(self):
        session = in_map()
        adapter = SessionMovement()
        old = adapter.spawn(session, Position(0, 0), 5)
        session.leave_map()
        session.join_map("map_a")
        self.assertIsNone(adapter.sync(session))
        self.assertTrue(old.closed)
        fresh = adapter.spawn(session, Position(0, 0), 5)
        self.assertIsNot(old, fresh)


if __name__ == "__main__":
    unittest.main()
