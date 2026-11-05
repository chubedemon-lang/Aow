"""Regression tests for synthetic durable quest award uniqueness."""
import sqlite3
import unittest

from server.quest_award_ledger import QuestAwardLedger, RewardConflict


class QuestAwardTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.ledger = QuestAwardLedger(self.db)

    def tearDown(self):
        self.db.close()

    def test_same_request_is_idempotent(self):
        self.assertTrue(self.ledger.grant_quest_once("a", "p", 1, "gem", 3))
        self.assertFalse(self.ledger.grant_quest_once("a", "p", 1, "gem", 3))
        self.assertEqual(self.ledger.balance("p", "gem"), 3)

    def test_new_request_cannot_repeat_same_quest_reward(self):
        self.ledger.grant_quest_once("a", "p", 1, "gem", 3)
        with self.assertRaises(RewardConflict):
            self.ledger.grant_quest_once("b", "p", 1, "gem", 3)
        self.assertEqual(self.ledger.balance("p", "gem"), 3)

    def test_conflicting_payload_rejected(self):
        self.ledger.grant_quest_once("a", "p", 1, "gem", 3)
        with self.assertRaises(RewardConflict):
            self.ledger.grant_quest_once("a", "p", 1, "gem", 4)
        self.assertEqual(self.ledger.balance("p", "gem"), 3)

    def test_reusing_request_for_other_quest_rejected(self):
        self.ledger.grant_quest_once("a", "p", 1, "gem", 3)
        with self.assertRaises(RewardConflict):
            self.ledger.grant_quest_once("a", "p", 2, "gem", 3)

    def test_distinct_players_and_quests(self):
        self.ledger.grant_quest_once("a", "p", 1, "gem", 3)
        self.ledger.grant_quest_once("b", "p", 2, "gem", 4)
        self.ledger.grant_quest_once("c", "other", 1, "gem", 5)
        self.assertEqual(self.ledger.balance("p", "gem"), 7)
        self.assertEqual(self.ledger.balance("other", "gem"), 5)

    def test_invalid_input_does_not_write(self):
        with self.assertRaises(ValueError):
            self.ledger.grant_quest_once("x", "p", True, "gem", 2)
        self.assertEqual(self.db.execute("SELECT count(*) FROM quest_award_keys").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
