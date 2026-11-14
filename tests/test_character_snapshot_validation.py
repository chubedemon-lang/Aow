"""Strict persisted character-row decoding across authorized readers."""
import sqlite3
import unittest

from server.character_snapshot import (
    CharacterSnapshot,
    CharacterSnapshotError,
    character_snapshot_from_row,
)
from server.sqlite_authorized_character_service import (
    SqliteAuthorizedCharacterService,
)
from server.sqlite_authorized_player_bootstrap_service import (
    SqliteAuthorizedPlayerBootstrapService,
)
from server.sqlite_authorized_world_state_service import (
    SqliteAuthorizedWorldStateService,
)
from server.sqlite_inventory_store import SqliteInventoryStore


class CharacterSnapshotValidationTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
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
               INSERT INTO accounts(id, username) VALUES (1, 'alice');"""
        )
        self.now = [50_000.0]
        self.characters = SqliteAuthorizedCharacterService(
            self.db, ttl_seconds=60, clock=lambda: self.now[0]
        )
        self.token = self.characters.sessions.issue(1)
        created = self.characters.create_with_initial_state(
            self.token, "Alice", level=3, experience=40
        )
        self.character_id = created.character.character_id

        inventory = SqliteInventoryStore(self.db)
        inventory.create(str(self.character_id), capacity=8, max_stack=20)
        self.world = SqliteAuthorizedWorldStateService(
            self.db, ttl_seconds=60, clock=lambda: self.now[0]
        )
        self.bootstrap = SqliteAuthorizedPlayerBootstrapService(
            self.db, ttl_seconds=60, clock=lambda: self.now[0]
        )

    def test_valid_row_is_preserved_without_coercion(self):
        row = (self.character_id, "Alice", "test_map", -12, 34)
        self.assertEqual(
            character_snapshot_from_row(row),
            CharacterSnapshot(self.character_id, "Alice", "test_map", -12, 34),
        )

    def test_malformed_storage_classes_and_values_are_rejected(self):
        valid_id = self.character_id
        invalid_rows = (
            (valid_id, b"Alice", "test_map", 0, 0),
            (valid_id, "Alice", b"test_map", 0, 0),
            (valid_id, "Alice", "test_map", 1.5, 0),
            (valid_id, "Alice", "test_map", 0, -1.5),
            (valid_id, "Bad\\x00Name", "test_map", 0, 0),
            (valid_id, "Alice", "bad/map", 0, 0),
            (valid_id, "Alice", "test_map", -(2**31) - 1, 0),
            (valid_id, "Alice", "test_map", 0, 2**31),
        )
        for row in invalid_rows:
            with self.subTest(row=row), self.assertRaises(CharacterSnapshotError):
                character_snapshot_from_row(row)

    def test_all_authorized_readers_fail_closed_on_corrupt_rows(self):
        corruptions = (
            ("x", 1.5),
            ("y", -2.5),
            ("name", sqlite3.Binary(b"Alice")),
            ("map_id", sqlite3.Binary(b"test_map")),
        )
        for column, value in corruptions:
            with self.subTest(column=column):
                self.db.execute(
                    f"UPDATE characters SET {column}=? WHERE id=?",
                    (value, self.character_id),
                )
                readers = (
                    lambda: self.characters.get(self.token, self.character_id),
                    lambda: self.characters.list_for_account(self.token),
                    lambda: self.world.get_snapshot(self.token, self.character_id),
                    lambda: self.bootstrap.get_snapshot(self.token, self.character_id),
                )
                for reader in readers:
                    with self.subTest(reader=reader), self.assertRaises(
                        CharacterSnapshotError
                    ):
                        reader()
                    self.assertFalse(self.db.in_transaction)
                self.db.execute(
                    f"UPDATE characters SET {column}=? WHERE id=?",
                    (
                        0 if column in ("x", "y") else (
                            "Alice" if column == "name" else "test_map"
                        ),
                        self.character_id,
                    ),
                )


if __name__ == "__main__":
    unittest.main()
