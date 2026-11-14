"""Regression tests for synthetic durable quest award uniqueness."""
import sqlite3
import unittest

from server.quest_award_ledger import QuestAwardLedger, RewardConflict


_MAX_SQLITE_INTEGER = 2**63 - 1


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

    def test_reward_balance_overflow_rolls_back_quest_and_receipt(self):
        self.ledger.grant_quest_once("max", "p", 1, "gem", _MAX_SQLITE_INTEGER)
        with self.assertRaisesRegex(RewardConflict, "integer range"):
            self.ledger.grant_quest_once("overflow", "p", 2, "gem", 1)
        self.assertEqual(self.ledger.balance("p", "gem"), _MAX_SQLITE_INTEGER)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_award_keys").fetchone()[0], 1
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 1
        )
        self.assertFalse(self.db.in_transaction)

    def test_quantity_above_sqlite_integer_range_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "quantity"):
            self.ledger.grant_quest_once(
                "too-large", "p", 1, "gem", _MAX_SQLITE_INTEGER + 1
            )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_award_keys").fetchone()[0], 0
        )

    def test_invalid_input_does_not_write(self):
        with self.assertRaises(ValueError):
            self.ledger.grant_quest_once("x", "p", True, "gem", 2)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_award_keys").fetchone()[0], 0
        )


    def test_rejects_caller_transaction_without_touching_caller_work(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (7)")

        with self.assertRaisesRegex(ValueError, "active transaction"):
            self.ledger.grant_quest_once("nested", "p", 2, "gem", 1)

        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM caller_work").fetchone()[0], 0
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_award_keys").fetchone()[0], 0
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 0
        )


if __name__ == "__main__":
    unittest.main()
