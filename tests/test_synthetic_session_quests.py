"""Synthetic quest tests; no proprietary AOW data."""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_quests import Quest, QuestError, SessionQuests


def ready():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("hero")
    return session


class QuestTests(unittest.TestCase):
    def test_progress_caps_and_completion(self):
        session = ready()
        quests = SessionQuests([Quest("kill_3", 3)])
        quests.initialize(session)
        quests.advance(session, "kill_3", 2)
        self.assertEqual(quests.progress[0].count, 2)
        quests.advance(session, "kill_3", 10)
        self.assertEqual(quests.progress[0].count, 3)
        self.assertTrue(quests.progress[0].completed)

    def test_invalid_catalog(self):
        for entries in ([Quest("a", 1), Quest("a", 2)],
                        [Quest("a", True)], [Quest("bad id", 1)],
                        [Quest("a", 0)], [object()]):
            with self.subTest(entries=repr(entries)):
                with self.assertRaises(QuestError):
                    SessionQuests(entries)

    def test_invalid_updates_are_atomic(self):
        session = ready()
        quests = SessionQuests([Quest("a", 3)])
        quests.initialize(session)
        for q, amount in (("a", 0), ("a", True), ("a", "1"),
                          ("missing", 1), ([], 1)):
            with self.subTest(q=repr(q), amount=repr(amount)):
                with self.assertRaises(QuestError):
                    quests.advance(session, q, amount)
                self.assertEqual(quests.progress[0].count, 0)

    def test_different_session_revokes_progress(self):
        first, second = ready(), ready()
        quests = SessionQuests([Quest("a", 2)])
        quests.initialize(first)
        quests.advance(first, "a")
        with self.assertRaises(QuestError):
            quests.advance(second, "a")
        self.assertIsNone(quests.progress)

    def test_duplicate_initialize_is_rejected(self):
        session = ready()
        quests = SessionQuests([Quest("a", 2)])
        quests.initialize(session)
        with self.assertRaises(QuestError):
            quests.initialize(session)

    def test_uninitialized_update_rejected(self):
        quests = SessionQuests([Quest("a", 2)])
        with self.assertRaises(QuestError):
            quests.advance(ready(), "a")


if __name__ == "__main__":
    unittest.main()
