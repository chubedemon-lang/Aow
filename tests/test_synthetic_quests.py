"""Regression tests for synthetic quest state; no APK compatibility implied."""
import unittest
from server.synthetic_quests import Quest, QuestBook, QuestProgress, MAX_COUNT


class QuestTests(unittest.TestCase):
    def setUp(self):
        self.quest = Quest(7, "defeat_dummy", 3)
        self.book = QuestBook(1).add(self.quest)

    def test_immutable_progress(self):
        newer = self.book.advance(7, "defeat_dummy")
        self.assertEqual(self.book.entries[0].count, 0)
        self.assertEqual(newer.entries[0].count, 1)

    def test_completion_and_claim_once(self):
        completed = self.book.advance(7, "defeat_dummy", 3)
        self.assertTrue(completed.entries[0].completed)
        claimed = completed.claim(7)
        self.assertTrue(claimed.entries[0].claimed)
        with self.assertRaises(ValueError):
            claimed.claim(7)
        with self.assertRaises(ValueError):
            claimed.advance(7, "defeat_dummy")

    def test_progress_capped(self):
        self.assertEqual(self.book.advance(7, "defeat_dummy", MAX_COUNT).entries[0].count, 3)

    def test_claim_before_completion_rejected(self):
        with self.assertRaises(ValueError):
            self.book.claim(7)

    def test_wrong_objective_rejected(self):
        with self.assertRaises(ValueError):
            self.book.advance(7, "other")

    def test_invalid_amounts_rejected(self):
        for amount in (0, -1, True, 1.5, MAX_COUNT + 1):
            with self.subTest(amount=amount), self.assertRaises(ValueError):
                self.book.advance(7, "defeat_dummy", amount)

    def test_unknown_quest_rejected(self):
        with self.assertRaises(ValueError):
            self.book.advance(8, "defeat_dummy")

    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            self.book.add(self.quest)

    def test_isolation_between_players(self):
        other = QuestBook(2).add(self.quest)
        self.book.advance(7, "defeat_dummy", 2)
        self.assertEqual(other.entries[0].count, 0)

    def test_invalid_states_rejected(self):
        with self.assertRaises(ValueError):
            QuestProgress(self.quest, count=True)
        with self.assertRaises(ValueError):
            QuestProgress(self.quest, count=1, claimed=True)
        with self.assertRaises(ValueError):
            Quest(1, "", 2)
        with self.assertRaises(ValueError):
            QuestBook(True)

    def test_multiple_quests_independent(self):
        book = self.book.add(Quest(8, "walk", 2))
        updated = book.advance(8, "walk")
        self.assertEqual([entry.count for entry in updated.entries], [0, 1])


if __name__ == "__main__":
    unittest.main()
