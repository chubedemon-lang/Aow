import unittest

from server.synthetic_session import Phase, SessionError, SyntheticSession


class SyntheticSessionTests(unittest.TestCase):
    def test_happy_path_and_map_reentry(self):
        s = SyntheticSession()
        s.authenticate("account")
        s.select_player("hero")
        s.enter_map(0)
        self.assertEqual((s.phase, s.map_id), (Phase.IN_MAP, 0))
        s.leave_map()
        self.assertEqual((s.phase, s.map_id), (Phase.PLAYER_SELECTED, None))
        s.enter_map(12)
        self.assertEqual(s.map_id, 12)

    def test_cannot_enter_map_before_authentication(self):
        s = SyntheticSession()
        with self.assertRaises(SessionError):
            s.enter_map(1)
        with self.assertRaises(SessionError):
            s.select_player("hero")
        self.assertEqual(s.phase, Phase.CONNECTED)

    def test_repeated_authentication_is_rejected(self):
        s = SyntheticSession()
        s.authenticate("one")
        with self.assertRaises(SessionError):
            s.authenticate("two")
        self.assertEqual(s.account_id, "one")

    def test_invalid_identifiers_do_not_advance_state(self):
        s = SyntheticSession()
        for value in ("", "  ", None, 3):
            with self.assertRaises(SessionError):
                s.authenticate(value)
        self.assertEqual(s.phase, Phase.CONNECTED)
        s.authenticate("one")
        for value in ("", " ", None, 2):
            with self.assertRaises(SessionError):
                s.select_player(value)
        self.assertEqual(s.phase, Phase.AUTHENTICATED)

    def test_invalid_map_does_not_mutate_state(self):
        s = SyntheticSession()
        s.authenticate("one")
        s.select_player("hero")
        for value in (-1, True, 1.5, "1", None):
            with self.assertRaises(SessionError):
                s.enter_map(value)
        self.assertEqual((s.phase, s.map_id), (Phase.PLAYER_SELECTED, None))

    def test_close_revokes_everything_and_is_terminal(self):
        s = SyntheticSession()
        s.authenticate("one")
        s.select_player("hero")
        s.enter_map(3)
        s.close()
        s.close()
        self.assertEqual((s.phase, s.account_id, s.player_id, s.map_id),
                         (Phase.CLOSED, None, None, None))
        for operation in (lambda: s.authenticate("two"),
                          lambda: s.select_player("other"),
                          lambda: s.enter_map(1),
                          s.leave_map):
            with self.assertRaises(SessionError):
                operation()

    def test_sessions_are_isolated(self):
        first, second = SyntheticSession(), SyntheticSession()
        first.authenticate("one")
        first.select_player("hero")
        first.enter_map(1)
        self.assertEqual(second.phase, Phase.CONNECTED)
        first.close()
        self.assertEqual(second.phase, Phase.CONNECTED)


if __name__ == "__main__":
    unittest.main()
