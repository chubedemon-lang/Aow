"""Ownership tests for the isolated synthetic SQLite quest-award facade."""
import os
import sqlite3
import threading
import tempfile
import unittest

from server.sessions import SessionError
from server.quest_award_ledger import RewardConflict
from server.sqlite_authorized_quest_award_service import (
    SqliteAuthorizedQuestAwardService,
)

from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedQuestAwardServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-quest.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        self.addCleanup(self.db.close)
        self.db.execute(
            """CREATE TABLE characters (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL
            )"""
        )
        self.db.executemany(
            "INSERT INTO characters(id, account_id) VALUES (?, ?)",
            ((101, 1), (202, 2)),
        )
        self.db.commit()
        self.now = [5000.0]
        self.service = SqliteAuthorizedQuestAwardService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_grant_once_and_read_reward_balance(self):
        self.assertTrue(self.service.grant_quest_once(
            self.owner_token, 101, "quest-1", 7, "gem", 3
        ))
        self.assertEqual(self.service.balance(self.owner_token, 101, "gem"), 3)
        self.assertFalse(self.service.grant_quest_once(
            self.owner_token, 101, "quest-1", 7, "gem", 3
        ))
        self.assertEqual(self.service.balance(self.owner_token, 101, "gem"), 3)

    def test_foreign_account_cannot_grant_or_read_balance(self):
        with self.assertRaises(SessionError):
            self.service.grant_quest_once(
                self.other_token, 101, "foreign-award", 7, "gem", 3
            )
        with self.assertRaises(SessionError):
            self.service.balance(self.other_token, 101, "gem")
        self.assertEqual(self.service.balance(self.owner_token, 101, "gem"), 0)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0],
            0,
        )

    def test_unknown_and_foreign_character_have_same_error(self):
        messages = []
        for character_id in (202, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.balance(self.owner_token, character_id, "gem")
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])

    def test_expired_session_cannot_grant_or_read(self):
        self.now[0] = 5030.0
        with self.assertRaises(SessionError):
            self.service.grant_quest_once(
                self.owner_token, 101, "expired-award", 7, "gem", 3
            )
        with self.assertRaises(SessionError):
            self.service.balance(self.owner_token, 101, "gem")
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0],
            0,
        )

    def test_revoked_session_cannot_grant_or_read(self):
        self.assertTrue(self.service.sessions.revoke(self.owner_token))
        with self.assertRaises(SessionError):
            self.service.grant_quest_once(
                self.owner_token, 101, "revoked-award", 7, "gem", 3
            )
        with self.assertRaises(SessionError):
            self.service.balance(self.owner_token, 101, "gem")

    def test_retry_is_reauthorized_and_conflicting_award_is_rejected(self):
        self.service.grant_quest_once(
            self.owner_token, 101, "stable-award", 7, "gem", 3
        )
        with self.assertRaises(RewardConflict):
            self.service.grant_quest_once(
                self.owner_token, 101, "second-award", 7, "gem", 3
            )
        with self.assertRaises(SessionError):
            self.service.grant_quest_once(
                self.other_token, 101, "stable-award", 7, "gem", 3
            )
        self.assertEqual(self.service.balance(self.owner_token, 101, "gem"), 3)

    def test_invalid_character_ids_fail_closed(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.grant_quest_once(
                    self.owner_token, value, "invalid", 7, "gem", 1
                )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM reward_receipts").fetchone()[0],
            0,
        )

    def test_missing_ownership_schema_has_no_database_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedQuestAwardService(db)
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertNotIn("durable_sessions", tables)
        self.assertNotIn("reward_balances", tables)
        self.assertNotIn("quest_award_keys", tables)



    def test_session_revocation_serializes_with_quest_award(self):
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_grant = self.service._ledger.grant_quest_once

        def paused_grant(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release quest award")
            return original_grant(*args, **kwargs)

        self.service._ledger.grant_quest_once = paused_grant

        def grant():
            try:
                outcome["granted"] = self.service.grant_quest_once(
                    self.owner_token, 101, "atomic-revoke-quest",
                    9, "gem", 2,
                )
            except BaseException as exc:
                outcome["grant_error"] = exc

        def revoke():
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                sessions = SqliteSessionStore(
                    connection, ttl_seconds=30, clock=lambda: self.now[0]
                )
                revoke_started.set()
                outcome["revoked"] = sessions.revoke(self.owner_token)
            except BaseException as exc:
                outcome["revoke_error"] = exc
            finally:
                connection.close()
                revoke_done.set()

        grant_thread = threading.Thread(target=grant)
        revoke_thread = threading.Thread(target=revoke)
        grant_thread.start()
        self.assertTrue(entered.wait(5))
        revoke_thread.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(revoke_done.wait(0.2))
        finally:
            release.set()
        grant_thread.join(5)
        revoke_thread.join(5)
        self.assertFalse(grant_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self.assertNotIn("grant_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertTrue(outcome["revoked"])
        self.assertTrue(outcome["granted"])
        self.assertEqual(self.service._ledger.balance("101", "gem"), 2)
        with self.assertRaises(SessionError):
            self.service.balance(self.owner_token, 101, "gem")


if __name__ == "__main__":
    unittest.main()
