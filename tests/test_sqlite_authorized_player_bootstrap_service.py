"""Atomic session-authorized synthetic player bootstrap snapshot tests."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_character_service import (
    SqliteAuthorizedCharacterService,
)
from server.sqlite_authorized_player_bootstrap_service import (
    AuthorizedPlayerBootstrapSnapshot,
    SqliteAuthorizedPlayerBootstrapService,
)
from server.sqlite_inventory_store import InventoryNotFound, SqliteInventoryStore
from server.sqlite_session_store import SqliteSessionStore
from server.synthetic_map_position import MapPosition
from server.synthetic_player_state import PlayerSnapshot


class SqliteAuthorizedPlayerBootstrapServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "bootstrap.sqlite3")
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(
            """CREATE TABLE accounts (
                   id INTEGER PRIMARY KEY,
                   username TEXT NOT NULL UNIQUE
               );
               CREATE TABLE characters (
                   id INTEGER PRIMARY KEY,
                   account_id INTEGER NOT NULL UNIQUE,
                   name TEXT NOT NULL,
                   map_id TEXT NOT NULL,
                   x INTEGER NOT NULL,
                   y INTEGER NOT NULL,
                   FOREIGN KEY(account_id) REFERENCES accounts(id)
               );
               CREATE TABLE wallets (
                   character_id INTEGER PRIMARY KEY,
                   balance INTEGER NOT NULL CHECK(balance >= 0),
                   FOREIGN KEY(character_id) REFERENCES characters(id)
               );
               INSERT INTO accounts(id, username) VALUES (1, 'alice'), (2, 'bob');"""
        )
        self.now = [20_000.0]
        self.characters = SqliteAuthorizedCharacterService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.characters.sessions.issue(1)
        self.other_token = self.characters.sessions.issue(2)
        self.created = self.characters.create_with_initial_state(
            self.owner_token, "Alice", level=6, experience=245
        )
        self.character_id = self.created.character.character_id

        self.inventory_store = SqliteInventoryStore(self.db)
        self.inventory_store.create(
            str(self.character_id), capacity=8, max_stack=20
        )
        self.inventory_store.apply(
            str(self.character_id), "bootstrap-seed", 0,
            [("potion", 3), ("ore", 2)],
        )
        self.service = SqliteAuthorizedPlayerBootstrapService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )

    def test_owner_receives_all_bootstrap_components_from_one_snapshot(self):
        result = self.service.get_snapshot(self.owner_token, self.character_id)
        self.assertIsInstance(result, AuthorizedPlayerBootstrapSnapshot)
        self.assertEqual(result.character, self.created.character)
        self.assertEqual(
            result.player_state,
            PlayerSnapshot(str(self.character_id), 6, 245, 0, 0),
        )
        self.assertEqual(result.map_position, MapPosition())
        self.assertEqual(result.inventory.character_id, str(self.character_id))
        self.assertEqual(result.inventory.capacity, 8)
        self.assertEqual(result.inventory.max_stack, 20)
        self.assertEqual(result.inventory.revision, 1)
        self.assertEqual(result.inventory.items, (("ore", 2), ("potion", 3)))

    def test_snapshot_read_does_not_create_or_mutate_domain_rows(self):
        tables = (
            "characters", "wallets",
            "player_state_snapshots", "player_state_mutations",
            "map_position_snapshots", "map_position_mutations",
            "inventory_snapshots", "inventory_items", "inventory_mutations",
        )
        before = {
            table: self.db.execute(
                "SELECT count(*) FROM " + table
            ).fetchone()[0]
            for table in tables
        }
        total_changes = self.db.total_changes

        self.service.get_snapshot(self.owner_token, self.character_id)

        after = {
            table: self.db.execute(
                "SELECT count(*) FROM " + table
            ).fetchone()[0]
            for table in tables
        }
        self.assertEqual(after, before)
        self.assertEqual(self.db.total_changes, total_changes)
        self.assertFalse(self.db.in_transaction)

    def test_missing_inventory_fails_closed_without_creating_one(self):
        bob = self.characters.create_with_initial_state(
            self.other_token, "Bob"
        )
        with self.assertRaises(InventoryNotFound):
            self.service.get_snapshot(
                self.other_token, bob.character.character_id
            )
        self.assertIsNone(
            self.db.execute(
                "SELECT 1 FROM inventory_snapshots WHERE character_id=?",
                (str(bob.character.character_id),),
            ).fetchone()
        )
        self.assertFalse(self.db.in_transaction)

    def test_foreign_and_unknown_character_ids_share_the_same_error(self):
        messages = []
        for token, character_id in (
            (self.other_token, self.character_id),
            (self.owner_token, 999),
        ):
            with self.assertRaises(SessionError) as caught:
                self.service.get_snapshot(token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])
        self.assertFalse(self.db.in_transaction)

    def test_expired_and_revoked_sessions_cannot_read_bootstrap_state(self):
        self.now[0] += 30
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, self.character_id)

        self.now[0] = 20_000.0
        fresh = self.service.sessions.issue(1)
        self.assertTrue(self.service.sessions.revoke(fresh))
        with self.assertRaises(SessionError):
            self.service.get_snapshot(fresh, self.character_id)
        self.assertFalse(self.db.in_transaction)

    def test_session_revocation_waits_for_the_complete_snapshot_read(self):
        revoker_db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.addCleanup(revoker_db.close)
        revoker = SqliteSessionStore(
            revoker_db, ttl_seconds=30, clock=lambda: self.now[0]
        )

        entered_inventory = threading.Event()
        release_inventory = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_get = self.service.inventories.get

        def paused_get(character_id):
            entered_inventory.set()
            if not release_inventory.wait(5):
                raise TimeoutError("test did not release bootstrap inventory read")
            return original_get(character_id)

        self.service.inventories.get = paused_get

        def read_snapshot():
            try:
                outcome["snapshot"] = self.service.get_snapshot(
                    self.owner_token, self.character_id
                )
            except BaseException as exc:
                outcome["read_error"] = exc

        def revoke_session():
            try:
                revoke_started.set()
                outcome["revoked"] = revoker.revoke(self.owner_token)
            except BaseException as exc:
                outcome["revoke_error"] = exc
            finally:
                revoke_done.set()

        reader = threading.Thread(target=read_snapshot)
        revoker_thread = threading.Thread(target=revoke_session)
        reader.start()
        self.assertTrue(entered_inventory.wait(5))
        revoker_thread.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(
                revoke_done.wait(0.2),
                "revocation must wait until the bootstrap read commits",
            )
        finally:
            release_inventory.set()

        reader.join(5)
        revoker_thread.join(5)
        self.assertFalse(reader.is_alive())
        self.assertFalse(revoker_thread.is_alive())
        self.assertNotIn("read_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertTrue(outcome["revoked"])
        self.assertEqual(
            outcome["snapshot"].inventory.items,
            (("ore", 2), ("potion", 3)),
        )
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, self.character_id)


if __name__ == "__main__":
    unittest.main()
