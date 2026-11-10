"""Session ownership tests for synthetic durable inventory only."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_inventory_service import (
    SqliteAuthorizedInventoryService,
)
from server.sqlite_inventory_store import (
    InventoryAlreadyExists,
    InventorySnapshot,
)
from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedInventoryServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-inventory.sqlite3")
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



    def test_session_revocation_serializes_with_inventory_mutation(self):
        self.service.create(self.owner_token, 101, max_stack=10)
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_apply = self.service._inventory.apply

        def paused_apply(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release inventory mutation")
            return original_apply(*args, **kwargs)

        self.service._inventory.apply = paused_apply

        def mutate():
            try:
                outcome["mutation"] = self.service.apply(
                    self.owner_token, 101, "atomic-revoke", 0, [("potion", 1)]
                )
            except BaseException as exc:
                outcome["mutation_error"] = exc

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

        mutation_thread = threading.Thread(target=mutate)
        revoke_thread = threading.Thread(target=revoke)
        mutation_thread.start()
        self.assertTrue(entered.wait(5))
        revoke_thread.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(
                revoke_done.wait(0.2),
                "session revocation must wait for the authorized mutation",
            )
        finally:
            release.set()
        mutation_thread.join(5)
        revoke_thread.join(5)
        self.assertFalse(mutation_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self.assertNotIn("mutation_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertTrue(outcome["revoked"])
        self.assertEqual(outcome["mutation"].snapshot.count("potion"), 1)
        with self.assertRaises(SessionError):
            self.service.get(self.owner_token, 101)


if __name__ == "__main__":
    unittest.main()
