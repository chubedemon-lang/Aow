"""Session ownership tests for synthetic durable inventory only."""
import os
import sqlite3
import tempfile
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_inventory_service import (
    SqliteAuthorizedInventoryService,
)
from server.sqlite_inventory_store import (
    InventoryAlreadyExists,
    InventorySnapshot,
)


class SqliteAuthorizedInventoryServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = os.path.join(self.temp.name, "authorized-inventory.sqlite3")
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
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
        self.now = [4000.0]
        self.service = SqliteAuthorizedInventoryService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_create_read_and_mutate_inventory(self):
        created = self.service.create(
            self.owner_token, 101, capacity=3, max_stack=10
        )
        self.assertEqual(created, InventorySnapshot("101", 3, 10, 0, ()))
        changed = self.service.apply(
            self.owner_token, 101, "grant-1", 0, [("potion", 3)]
        )
        self.assertFalse(changed.replayed)
        self.assertEqual(changed.snapshot.count("potion"), 3)
        self.assertEqual(changed.snapshot.revision, 1)
        self.assertEqual(
            self.service.get(self.owner_token, 101), changed.snapshot
        )

    def test_foreign_account_cannot_create_read_or_mutate_inventory(self):
        self.service.create(self.owner_token, 101)
        attempts = (
            lambda: self.service.create(self.other_token, 101),
            lambda: self.service.get(self.other_token, 101),
            lambda: self.service.apply(
                self.other_token, 101, "foreign-grant", 0, [("potion", 1)]
            ),
        )
        for attempt in attempts:
            with self.subTest(attempt=attempt), self.assertRaises(SessionError):
                attempt()
        self.assertEqual(self.service.get(self.owner_token, 101).items, ())
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM inventory_mutations"
            ).fetchone()[0],
            0,
        )

    def test_unknown_and_foreign_character_have_same_authorization_error(self):
        messages = []
        for character_id in (202, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.get(self.owner_token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])

    def test_expired_session_cannot_create_read_or_mutate(self):
        self.service.create(self.owner_token, 101)
        self.now[0] = 4030.0
        with self.assertRaises(SessionError):
            self.service.get(self.owner_token, 101)
        with self.assertRaises(SessionError):
            self.service.apply(
                self.owner_token, 101, "expired", 0, [("potion", 1)]
            )
        with self.assertRaises(SessionError):
            self.service.create(self.owner_token, 101)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM inventory_mutations"
            ).fetchone()[0],
            0,
        )

    def test_revoked_session_cannot_read_or_mutate(self):
        self.service.create(self.owner_token, 101)
        self.assertTrue(self.service.sessions.revoke(self.owner_token))
        with self.assertRaises(SessionError):
            self.service.get(self.owner_token, 101)
        with self.assertRaises(SessionError):
            self.service.apply(
                self.owner_token, 101, "revoked", 0, [("potion", 1)]
            )

    def test_idempotent_replay_is_authorized_again(self):
        self.service.create(self.owner_token, 101, max_stack=10)
        first = self.service.apply(
            self.owner_token, 101, "stable-grant", 0, [("potion", 1)]
        )
        self.service.apply(
            self.owner_token, 101, "later-grant", 1, [("potion", 2)]
        )
        replay = self.service.apply(
            self.owner_token, 101, "stable-grant", 0, [("potion", 1)]
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        with self.assertRaises(SessionError):
            self.service.apply(
                self.other_token, 101, "stable-grant", 0, [("potion", 1)]
            )
        self.assertEqual(self.service.get(self.owner_token, 101).count("potion"), 3)

    def test_invalid_character_ids_fail_closed(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.create(self.owner_token, value)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM inventory_snapshots"
            ).fetchone()[0],
            0,
        )

    def test_duplicate_creation_is_rejected_after_authorization(self):
        self.service.create(self.owner_token, 101)
        with self.assertRaises(InventoryAlreadyExists):
            self.service.create(self.owner_token, 101)

    def test_missing_ownership_schema_has_no_database_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedInventoryService(db)
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertNotIn("durable_sessions", tables)
        self.assertNotIn("inventory_snapshots", tables)
        self.assertNotIn("inventory_mutations", tables)


if __name__ == "__main__":
    unittest.main()
