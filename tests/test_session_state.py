"""Synthetic session lifecycle tests; not an APK integration test."""
import unittest
from server.session_state import Session, SessionState, SessionTransitionError


class SessionTests(unittest.TestCase):
    def test_happy_path_and_reentry(self):
        s = Session("connection-1")
        s.authenticate("player-1")
        self.assertEqual(s.state, SessionState.AUTHENTICATED)
        s.enter_world()
        self.assertEqual(s.state, SessionState.IN_WORLD)
        s.leave_world()
        s.enter_world()
        s.close()
        self.assertEqual(s.state, SessionState.CLOSED)
        self.assertIsNone(s.player_id)

    def test_world_requires_login(self):
        with self.assertRaises(SessionTransitionError):
            Session("s").enter_world()

    def test_duplicate_login_rejected(self):
        s = Session("s")
        s.authenticate("p")
        with self.assertRaises(SessionTransitionError):
            s.authenticate("another")
        self.assertEqual(s.player_id, "p")

    def test_close_is_terminal(self):
        s = Session("s")
        s.close()
        with self.assertRaises(SessionTransitionError):
            s.authenticate("p")
        with self.assertRaises(SessionTransitionError):
            s.enter_world()

    def test_invalid_ids_do_not_change_state(self):
        s = Session("s")
        for invalid in ("", "x" * 129, None, 3):
            with self.assertRaises(ValueError):
                s.authenticate(invalid)
        self.assertEqual(s.state, SessionState.CONNECTED)
        with self.assertRaises(ValueError):
            Session("")

    def test_invalid_initial_state_rejected(self):
        with self.assertRaises(ValueError):
            Session("s", SessionState.AUTHENTICATED)
        with self.assertRaises(TypeError):
            Session("s", "connected")

    def test_leave_world_requires_world(self):
        s = Session("s")
        with self.assertRaises(SessionTransitionError):
            s.leave_world()
        s.authenticate("p")
        with self.assertRaises(SessionTransitionError):
            s.leave_world()


if __name__ == "__main__":
    unittest.main()
