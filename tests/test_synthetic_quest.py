import unittest

from server.synthetic_quest import QuestError, QuestJournal


class QuestJournalTests(unittest.TestCase):
    def setUp(self):
        self.journal = QuestJournal({"first_steps": 3})

    def test_progress_and_claim(self):
        self.assertEqual(self.journal.advance("alice", "first_steps", 2), 2)
        self.assertEqual(self.journal.advance("alice", "first_steps", 9), 3)
        self.assertTrue(self.journal.claim("alice", "first_steps"))
        self.assertEqual(self.journal.progress("alice", "first_steps"), (3, True))

    def test_cannot_claim_twice(self):
        self.journal.advance("alice", "first_steps", 3)
        self.journal.claim("alice", "first_steps")
        with self.assertRaises(QuestError):
            self.journal.claim("alice", "first_steps")
        with self.assertRaises(QuestError):
            self.journal.advance("alice", "first_steps")

    def test_cannot_claim_incomplete(self):
        with self.assertRaises(QuestError):
            self.journal.claim("alice", "first_steps")

    def test_players_isolated(self):
        self.journal.advance("alice", "first_steps")
        self.assertEqual(self.journal.progress("bob", "first_steps"), (0, False))

    def test_reject_invalid_amount(self):
        for amount in (0, -1, True, 1.5, "2"):
            with self.assertRaises(QuestError):
                self.journal.advance("alice", "first_steps", amount)
        self.assertEqual(self.journal.progress("alice", "first_steps"), (0, False))

    def test_reject_invalid_configuration(self):
        for targets in ({}, {"x": 0}, {"": 2}, {"x": True}):
            with self.assertRaises(QuestError):
                QuestJournal(targets)

    def test_unknown_quest_and_player(self):
        with self.assertRaises(QuestError):
            self.journal.advance("alice", "unknown")
        with self.assertRaises(QuestError):
            self.journal.progress("", "first_steps")


if __name__ == "__main__":
    unittest.main()
