"""Tests for atomic session-authorized synthetic quest inventory awards."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_inventory_service import SqliteAuthorizedInventoryService
from server.sqlite_authorized_quest_inventory_award_service import (
    SqliteAuthorizedQuestInventoryAwardService,
)
from server.sqlite_quest_inventory_award_store import (
    QuestInventoryAwardConflict,
    QuestInventoryAwardError,
)
from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedQuestInventoryAwardServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "quest-inventory.sqlite3")
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
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
        self.now = [7000.0]
        self.service = SqliteAuthorizedQuestInventoryAwardService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)
        self.inventory = SqliteAuthorizedInventoryService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.inventory.create(self.owner_token, 101, capacity=4, max_stack=10)

    def test_owner_receives_item_once_in_authoritative_inventory(self):
        result = self.service.grant_once(
            self.owner_token, 101, "quest-7-award", 0, 7, "gem", 3
        )
        self.assertTrue(result.awarded)
        self.assertFalse(result.replayed)
        self.assertEqual(result.snapshot.count("gem"), 3)
        self.assertEqual(result.snapshot.revision, 1)
        self.assertEqual(
            self.inventory.get(self.owner_token, 101), result.snapshot
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_inventory_awards").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            1,
        )

    def test_exact_retry_returns_original_receipt_without_double_grant(self):
        first = self.service.grant_once(
            self.owner_token, 101, "quest-7-award", 0, 7, "gem", 3
        )
        self.inventory.apply(
            self.owner_token, 101, "later-potion", 1, [("potion", 1)]
        )
        replay = self.service.grant_once(
            self.owner_token, 101, "quest-7-award", 0, 7, "gem", 3
        )
        self.assertFalse(replay.awarded)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        current = self.inventory.get(self.owner_token, 101)
        self.assertEqual(current.count("gem"), 3)
        self.assertEqual(current.count("potion"), 1)
        self.assertEqual(current.revision, 2)

    def test_same_quest_item_cannot_be_awarded_with_a_new_request(self):
        self.service.grant_once(
            self.owner_token, 101, "quest-7-award", 0, 7, "gem", 3
        )
        with self.assertRaises(QuestInventoryAwardConflict):
            self.service.grant_once(
                self.owner_token, 101, "quest-7-second", 1, 7, "gem", 3
            )
        self.assertEqual(self.inventory.get(self.owner_token, 101).count("gem"), 3)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            1,
        )

    def test_request_id_cannot_be_reused_for_a_different_payload(self):
        self.service.grant_once(
            self.owner_token, 101, "stable-award", 0, 7, "gem", 2
        )
        with self.assertRaises(QuestInventoryAwardConflict):
            self.service.grant_once(
                self.owner_token, 101, "stable-award", 1, 8, "potion", 1
            )
        self.assertEqual(self.inventory.get(self.owner_token, 101).items, (("gem", 2),))

    def test_foreign_account_cannot_grant(self):
        with self.assertRaises(SessionError):
            self.service.grant_once(
                self.other_token, 101, "foreign-award", 0, 7, "gem", 1
            )
        self.assertEqual(self.inventory.get(self.owner_token, 101).items, ())
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_inventory_awards").fetchone()[0],
            0,
        )

    def test_expired_and_revoked_sessions_cannot_grant(self):
        self.now[0] = 7030.0
        with self.assertRaises(SessionError):
            self.service.grant_once(
                self.owner_token, 101, "expired-award", 0, 7, "gem", 1
            )
        self.now[0] = 7000.0
        self.assertTrue(self.service.sessions.revoke(self.owner_token))
        with self.assertRaises(SessionError):
            self.service.grant_once(
                self.owner_token, 101, "revoked-award", 0, 7, "gem", 1
            )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_inventory_awards").fetchone()[0],
            0,
        )

    def test_inventory_failure_rolls_back_award_receipt(self):
        self.inventory.apply(
            self.owner_token, 101, "fill-stack", 0, [("gem", 9)]
        )
        with self.assertRaises(ValueError):
            self.service.grant_once(
                self.owner_token, 101, "too-many-gems", 1, 7, "gem", 2
            )
        self.assertEqual(self.inventory.get(self.owner_token, 101).count("gem"), 9)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_inventory_awards").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            1,
        )

    def test_invalid_values_fail_closed(self):
        invalid = (
            (True, "gem", 1),
            (-1, "gem", 1),
            (7, "bad item", 1),
            (7, "gem", True),
            (7, "gem", 0),
        )
        for quest_id, item_id, quantity in invalid:
            with self.subTest(quest_id=quest_id, item_id=item_id, quantity=quantity):
                with self.assertRaises(QuestInventoryAwardError):
                    self.service.grant_once(
                        self.owner_token, 101, "invalid-" + str(len(invalid)),
                        0, quest_id, item_id, quantity,
                    )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_inventory_awards").fetchone()[0],
            0,
        )

    def test_missing_ownership_schema_has_no_database_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedQuestInventoryAwardService(db)
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertEqual(tables, set())

    def test_session_revocation_serializes_with_inventory_award(self):
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_apply = self.service._inventory.apply

        def paused_apply(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release inventory award")
            return original_apply(*args, **kwargs)

        self.service._inventory.apply = paused_apply

        def grant():
            try:
                outcome["award"] = self.service.grant_once(
                    self.owner_token, 101, "atomic-revoke-award",
                    0, 9, "gem", 2,
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
        self.assertTrue(outcome["award"].awarded)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM quest_inventory_awards").fetchone()[0],
            1,
        )
        with self.assertRaises(SessionError):
            self.service.grant_once(
                self.owner_token, 101, "after-revoke", 1, 10, "potion", 1
            )


if __name__ == "__main__":
    unittest.main()
