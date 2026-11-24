"""Synthetic movement must revoke an actor on a rejected move after close."""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_movement import SessionMovement
from server.synthetic_movement import MovementError, Position


class ClosedMoveTests(unittest.TestCase):
    def test_closed_session_move_revokes_actor(self):
        session = SyntheticSession()
        session.authenticate()
        session.select_character("player_1")
        session.join_map("map_1")
        adapter = SessionMovement()
        actor = adapter.spawn(session, Position(0, 0), 5)
        session.close()
        with self.assertRaises(MovementError):
            adapter.move(session, 1, Position(1, 0))
        self.assertTrue(actor.closed)
        self.assertIsNone(adapter.actor)

    def test_departed_session_move_revokes_actor(self):
        session = SyntheticSession()
        session.authenticate()
        session.select_character("player_1")
        session.join_map("map_1")
        adapter = SessionMovement()
        actor = adapter.spawn(session, Position(0, 0), 5)
        session.leave_map()
        with self.assertRaises(MovementError):
            adapter.move(session, 1, Position(1, 0))
        self.assertTrue(actor.closed)
        self.assertIsNone(adapter.actor)


if __name__ == "__main__":
    unittest.main()
