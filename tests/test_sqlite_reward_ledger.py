"""Synthetic SQLite reward persistence regression tests."""
import os
import sqlite3
import tempfile
import unittest

from server.sqlite_reward_ledger import RewardConflict, SqliteRewardLedger


_MAX_SQLITE_INTEGER = 2**63 - 1


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
        cases = [
            ("", "p", 1, "gem", 1),
            ("a", "", 1, "gem", 1),
            ("a", "p", True, "gem", 1),
            ("a", "p", 1, "gem", True),
            ("a", "p", 1, "gem", 0),
            ("a", "p", 1, "gem", _MAX_SQLITE_INTEGER + 1),
        ]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.ledger.grant_once(*args)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 0
        )

    def test_balance_accepts_maximum_sqlite_integer_but_rejects_overflow(self):
        self.assertTrue(
            self.ledger.grant_once("max", "p1", 3, "gem", _MAX_SQLITE_INTEGER)
        )
        self.assertEqual(self.ledger.balance("p1", "gem"), _MAX_SQLITE_INTEGER)
        with self.assertRaisesRegex(RewardConflict, "integer range"):
            self.ledger.grant_once("overflow", "p1", 4, "gem", 1)
        self.assertEqual(self.ledger.balance("p1", "gem"), _MAX_SQLITE_INTEGER)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 1
        )
        self.assertFalse(self.db.in_transaction)

    def test_legacy_real_balance_fails_closed_without_partial_receipt(self):
        legacy = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(legacy.close)
        legacy.executescript(
            """CREATE TABLE reward_balances (
                   player_id TEXT NOT NULL, item_id TEXT NOT NULL,
                   quantity INTEGER NOT NULL CHECK(quantity >= 0),
                   PRIMARY KEY(player_id, item_id));
               CREATE TABLE reward_receipts (
                   request_id TEXT PRIMARY KEY, player_id TEXT NOT NULL,
                   quest_id INTEGER NOT NULL, item_id TEXT NOT NULL,
                   quantity INTEGER NOT NULL CHECK(quantity > 0));
               INSERT INTO reward_balances VALUES ('p1', 'gem', 1.5);"""
        )
        ledger = SqliteRewardLedger(legacy)
        with self.assertRaisesRegex(RewardConflict, "valid SQLite integer"):
            ledger.grant_once("new", "p1", 5, "gem", 1)
        with self.assertRaisesRegex(RewardConflict, "valid SQLite integer"):
            ledger.balance("p1", "gem")
        self.assertEqual(
            legacy.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 0
        )
        self.assertFalse(legacy.in_transaction)

    def test_second_connection_replay(self):
        self.ledger.grant_once("a", "p", 1, "gem", 3)
        second = sqlite3.connect(self.path)
        try:
            other = SqliteRewardLedger(second)
            self.assertFalse(other.grant_once("a", "p", 1, "gem", 3))
            self.assertEqual(other.balance("p", "gem"), 3)
        finally:
            second.close()

    def test_constructor_rejects_non_sqlite_connection(self):
        with self.assertRaises(TypeError):
            SqliteRewardLedger(None)

    def test_constructor_does_not_commit_caller_transaction(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        try:
            connection.execute("CREATE TABLE caller_work (value INTEGER)")
            connection.execute("BEGIN")
            connection.execute("INSERT INTO caller_work VALUES (1)")
            with self.assertRaisesRegex(ValueError, "active transaction"):
                SqliteRewardLedger(connection)
            self.assertTrue(connection.in_transaction)
            connection.rollback()
            self.assertEqual(
                connection.execute("SELECT count(*) FROM caller_work").fetchone()[0],
                0,
            )
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertNotIn("reward_balances", tables)
            self.assertNotIn("reward_receipts", tables)
        finally:
            connection.close()

    def test_grant_rejects_caller_transaction_without_rolling_it_back(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (7)")
        with self.assertRaisesRegex(ValueError, "active transaction"):
            self.ledger.grant_once("nested", "p1", 3, "gem", 2)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM caller_work").fetchone()[0], 0
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0], 0
        )


if __name__ == "__main__":
    unittest.main()
