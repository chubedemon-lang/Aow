"""Synthetic lifecycle tests; no APK protocol compatibility implied."""
import unittest

from server.synthetic_session_lifecycle import (
    SessionState, SessionTransitionError, SyntheticSession
)


class SessionLifecycleTests(unittest.TestCase):
    def test_happy_path_and_reentry(self):
        s = SyntheticSession()
        self.assertEqual(s.snapshot.state, SessionState.CONNECTED)
        s.authenticate()
        s.select_character("player_1")
        s.join_map("map_2")
        self.assertEqual(s.snapshot.map_id, "map_2")
        s.leave_map()
        self.assertIsNone(s.snapshot.map_id)
        self.assertEqual(s.snapshot.player_id, "player_1")
        s.join_map("map_3")
        self.assertEqual(s.snapshot.map_id, "map_3")

    def test_reject_out_of_order_without_mutation(self):
        s = SyntheticSession()
        original = s.snapshot
        with self.assertRaises(SessionTransitionError):
            s.join_map("test")
        self.assertEqual(s.snapshot, original)
        with self.assertRaises(SessionTransitionError):
            s.select_character("p")
        self.assertEqual(s.snapshot, original)

    def test_invalid_player_identifier_keeps_auth_state(self):
        s = SyntheticSession()
        s.authenticate()
        for bad in ("", "a/b", "é", "x" * 129, None, 1, "a b"):
            with self.subTest(bad=bad):
                with self.assertRaises(SessionTransitionError):
                    s.select_character(bad)
                self.assertEqual(s.snapshot.state, SessionState.AUTHENTICATED)

    def test_invalid_map_keeps_character_state(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("p")
        for bad in ("", "../secret", "a b", "x" * 129):
            with self.subTest(bad=bad):
                with self.assertRaises(SessionTransitionError):
                    s.join_map(bad)
                self.assertEqual(s.snapshot.state, SessionState.CHARACTER_READY)

    def test_double_authentication_rejected(self):
        s = SyntheticSession()
        s.authenticate()
        with self.assertRaises(SessionTransitionError):
            s.authenticate()

    def test_cannot_select_another_character_in_map(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("p")
        s.join_map("m")
        with self.assertRaises(SessionTransitionError):
            s.select_character("other")
        self.assertEqual(s.snapshot.player_id, "p")

    def test_close_clears_identity_and_is_idempotent(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("p")
        s.join_map("m")
        s.close()
        self.assertEqual(s.snapshot.state, SessionState.CLOSED)
        self.assertIsNone(s.snapshot.player_id)
        self.assertIsNone(s.snapshot.map_id)
        self.assertEqual(s.close(), s.snapshot)

    def test_closed_session_never_reopens(self):
        s = SyntheticSession()
        s.close()
        for action in (s.authenticate, lambda: s.select_character("p"),
                       lambda: s.join_map("m"), s.leave_map):
            with self.assertRaises(SessionTransitionError):
                action()
        self.assertEqual(s.snapshot.state, SessionState.CLOSED)


if __name__ == "__main__":
    unittest.main()
