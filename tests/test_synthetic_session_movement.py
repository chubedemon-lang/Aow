"""Synthetic session-to-movement integration tests; no AOW wire assertions."""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_movement import MovementError, Position
from server.synthetic_session_movement import SessionMovement


def ready_session(map_id="map_1"):
    session = SyntheticSession()
    session.authenticate()
    session.select_character("player_1")
    session.join_map(map_id)
    return session


class SessionMovementTests(unittest.TestCase):
    def test_spawn_move_and_monotonic_tick(self):
        session = ready_session()
        movement = SessionMovement()
        movement.spawn(session, Position(0, 0), 5)
        self.assertEqual(movement.move(session, 1, Position(3, 4)), Position(3, 4))
        with self.assertRaises(MovementError):
            movement.move(session, 1, Position(4, 4))
        self.assertEqual(movement.actor.position, Position(3, 4))

    def test_cannot_spawn_or_move_without_map(self):
        session = SyntheticSession()
        movement = SessionMovement()
        with self.assertRaises(MovementError):
            movement.spawn(session, Position(0, 0), 5)
        with self.assertRaises(MovementError):
            movement.move(session, 0, Position(0, 0))
        self.assertIsNone(movement.actor)

    def test_map_exit_revokes_actor_and_requires_respawn(self):
        session = ready_session()
        movement = SessionMovement()
        old_actor = movement.spawn(session, Position(0, 0), 2)
        session.leave_map()
        self.assertIsNone(movement.sync(session))
        self.assertTrue(old_actor.closed)
        session.join_map("map_2")
        with self.assertRaises(MovementError):
            movement.move(session, 0, Position(1, 1))
        new_actor = movement.spawn(session, Position(9, 9), 2)
        self.assertIsNot(new_actor, old_actor)
        self.assertEqual(movement.move(session, 0, Position(10, 9)), Position(10, 9))

    def test_map_change_rejects_stale_movement_even_without_sync(self):
        session = ready_session()
        movement = SessionMovement()
        old_actor = movement.spawn(session, Position(0, 0), 5)
        session.leave_map()
        session.join_map("map_2")
        with self.assertRaises(MovementError):
            movement.move(session, 2, Position(1, 1))
        self.assertTrue(old_actor.closed)
        self.assertIsNone(movement.actor)

    def test_close_revokes_position(self):
        session = ready_session()
        movement = SessionMovement()
        actor = movement.spawn(session, Position(0, 0), 5)
        session.close()
        movement.sync(session)
        self.assertTrue(actor.closed)
        with self.assertRaises(MovementError):
            movement.move(session, 1, Position(1, 1))

    def test_failed_spawn_does_not_bind_actor(self):
        session = ready_session()
        movement = SessionMovement()
        with self.assertRaises(MovementError):
            movement.spawn(session, Position(0, 0), 0)
        self.assertIsNone(movement.actor)
        movement.spawn(session, Position(0, 0), 1)
        with self.assertRaises(MovementError):
            movement.spawn(session, Position(1, 1), 1)


if __name__ == "__main__":
    unittest.main()
