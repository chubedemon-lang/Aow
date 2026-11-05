"""Synthetic SQLite reward persistence regression tests."""
import os
import sqlite3
import tempfile
import unittest

from server.sqlite_reward_ledger import RewardConflict, SqliteRewardLedger


class DurableRewardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.temp.name, "rewards.sqlite3")
        self.db = sqlite3.connect(self.path)
        self.ledger = SqliteRewardLedger(self.db)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_grant_and_replay(self):
        self.assertTrue(self.ledger.grant_once("r1", "p1", 3, "gem", 2))
        self.assertFalse(self.ledger.grant_once("r1", "p1", 3, "gem", 2))
        self.assertEqual(self.ledger.balance("p1", "gem"), 2)

    def test_conflicting_replay_is_rejected_without_mutation(self):
        self.ledger.grant_once("r1", "p1", 3, "gem", 2)
        with self.assertRaises(RewardConflict):
            self.ledger.grant_once("r1", "p1", 3, "gem", 4)
        self.assertEqual(self.ledger.balance("p1", "gem"), 2)

    def test_reopen_retains_receipt(self):
        self.ledger.grant_once("r1", "p1", 3, "gem", 2)
        self.db.close()
        self.db = sqlite3.connect(self.path)
        self.ledger = SqliteRewardLedger(self.db)
        self.assertFalse(self.ledger.grant_once("r1", "p1", 3, "gem", 2))
        self.assertEqual(self.ledger.balance("p1", "gem"), 2)

    def test_isolated_players_and_items(self):
        self.ledger.grant_once("a", "p1", 3, "gem", 2)
        self.ledger.grant_once("b", "p2", 3, "gem", 4)
        self.ledger.grant_once("c", "p1", 4, "coin", 5)
        self.assertEqual(self.ledger.balance("p1", "gem"), 2)
        self.assertEqual(self.ledger.balance("p2", "gem"), 4)
        self.assertEqual(self.ledger.balance("p1", "coin"), 5)

    def test_invalid_inputs(self):
        cases = [("", "p", 1, "gem", 1), ("a", "", 1, "gem", 1),
                 ("a", "p", True, "gem", 1), ("a", "p", 1, "gem", True),
                 ("a", "p", 1, "gem", 0)]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.ledger.grant_once(*args)
        self.assertEqual(self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 0)

    def test_second_connection_replay(self):
        self.ledger.grant_once("a", "p", 1, "gem", 3)
        second = sqlite3.connect(self.path)
        try:
            other = SqliteRewardLedger(second)
            self.assertFalse(other.grant_once("a", "p", 1, "gem", 3))
            self.assertEqual(other.balance("p", "gem"), 3)
        finally:
            second.close()


if __name__ == "__main__":
    unittest.main()
