"""Tests for local synthetic session logic, not APK compatibility."""
import unittest

from server.synthetic_session_state import Phase, Session, SessionError


class SessionStateTests(unittest.TestCase):
    def test_happy_path_and_map_reentry(self):
        session = Session()
        session.authenticate("account")
        session.select_character("hero")
        session.join_map(0)
        self.assertEqual(session.snapshot.phase, Phase.IN_MAP)
        self.assertEqual(session.snapshot.map_id, 0)
        session.leave_map()
        session.join_map(23)
        self.assertEqual(session.snapshot.map_id, 23)

    def test_reject_out_of_order_without_mutation(self):
        session = Session()
        before = session.snapshot
        with self.assertRaises(SessionError):
            session.select_character("hero")
        self.assertEqual(session.snapshot, before)
        with self.assertRaises(SessionError):
            session.join_map(1)
        self.assertEqual(session.snapshot, before)

    def test_reject_invalid_auth_atomically(self):
        for value in ("", " ", None, 4, "a" * 129):
            session = Session()
            with self.subTest(value=value), self.assertRaises(SessionError):
                session.authenticate(value)
            self.assertEqual(session.snapshot.phase, Phase.NEW)

    def test_reject_invalid_character_atomically(self):
        session = Session()
        session.authenticate("account")
        before = session.snapshot
        for value in ("", None, 2, "x" * 129):
            with self.subTest(value=value), self.assertRaises(SessionError):
                session.select_character(value)
            self.assertEqual(session.snapshot, before)

    def test_map_id_rejects_bool_and_out_of_range(self):
        session = Session()
        session.authenticate("a")
        session.select_character("b")
        before = session.snapshot
        for value in (True, -1, 2**31, "1", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                session.join_map(value)
            self.assertEqual(session.snapshot, before)

    def test_replay_transitions_rejected(self):
        session = Session()
        session.authenticate("a")
        with self.assertRaises(SessionError):
            session.authenticate("b")
        session.select_character("b")
        with self.assertRaises(SessionError):
            session.select_character("c")
        session.join_map(1)
        with self.assertRaises(SessionError):
            session.join_map(2)
        self.assertEqual(session.snapshot.map_id, 1)

    def test_close_erases_identifiers_and_is_terminal(self):
        session = Session()
        session.authenticate("secret-account")
        session.select_character("secret-character")
        session.join_map(1)
        session.close()
        session.close()
        self.assertEqual(session.snapshot.phase, Phase.CLOSED)
        self.assertIsNone(session.snapshot.account_id)
        self.assertIsNone(session.snapshot.character_id)
        self.assertIsNone(session.snapshot.map_id)
        for operation in (lambda: session.authenticate("a"),
                          lambda: session.select_character("b"),
                          lambda: session.join_map(1),
                          session.leave_map):
            with self.assertRaises(SessionError):
                operation()

    def test_sessions_are_isolated(self):
        first, second = Session(), Session()
        first.authenticate("a")
        first.close()
        self.assertEqual(second.snapshot.phase, Phase.NEW)


if __name__ == "__main__":
    unittest.main()
