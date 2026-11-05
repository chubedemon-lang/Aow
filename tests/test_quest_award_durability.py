"""Disk-backed regression tests for synthetic quest award durability and locking."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.quest_award_ledger import QuestAwardLedger, RewardConflict


class QuestAwardDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "rewards.sqlite")

    def tearDown(self):
        self.tmp.cleanup()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        return db, QuestAwardLedger(db)

    def test_restart_replay_does_not_duplicate_balance(self):
        db, ledger = self.connect()
        self.assertTrue(ledger.grant_quest_once("receipt", "player", 9, "coin", 7))
        db.close()
        db, ledger = self.connect()
        try:
            self.assertFalse(ledger.grant_quest_once("receipt", "player", 9, "coin", 7))
            self.assertEqual(ledger.balance("player", "coin"), 7)
        finally:
            db.close()

    def test_restart_conflicting_request_is_rejected(self):
        db, ledger = self.connect()
        ledger.grant_quest_once("first", "player", 9, "coin", 7)
        db.close()
        db, ledger = self.connect()
        try:
            with self.assertRaises(RewardConflict):
                ledger.grant_quest_once("second", "player", 9, "coin", 7)
            self.assertEqual(ledger.balance("player", "coin"), 7)
        finally:
            db.close()

    def test_two_connections_race_same_quest_item(self):
        # Each worker owns its own connection. BEGIN IMMEDIATE serializes writes.
        barrier = threading.Barrier(2)
        outcomes = []
        errors = []
        lock = threading.Lock()

        def worker(request_id):
            try:
                db, ledger = self.connect()
                try:
                    barrier.wait(timeout=5)
                    try:
                        outcome = ledger.grant_quest_once(
                            request_id, "player", 9, "coin", 7
                        )
                    except RewardConflict:
                        outcome = "conflict"
                    with lock:
                        outcomes.append(outcome)
                finally:
                    db.close()
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(request_id,))
            for request_id in ("one", "two")
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertCountEqual(outcomes, [True, "conflict"])
        db, ledger = self.connect()
        try:
            self.assertEqual(ledger.balance("player", "coin"), 7)
            self.assertEqual(
                db.execute("SELECT count(*) FROM quest_award_keys").fetchone()[0], 1
            )
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
