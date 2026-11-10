"""Tests for authenticated synthetic character creation and selection."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_character_service import (
    CharacterAlreadyExists,
    CharacterSnapshot,
    SqliteAuthorizedCharacterService,
)


class SqliteAuthorizedCharacterServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "characters.sqlite3")
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
        self.now = [5_000.0]
        self.service = SqliteAuthorizedCharacterService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_create_list_and_read_character(self):
        created = self.service.create(self.owner_token, "Alice")
        self.assertEqual(
            created, CharacterSnapshot(1, "Alice", "test_map", 0, 0)
        )
        self.assertEqual(self.service.list_for_account(self.owner_token), (created,))
        self.assertEqual(self.service.get(self.owner_token, created.character_id), created)
        self.assertEqual(
            self.db.execute(
                "SELECT balance FROM wallets WHERE character_id = ?",
                (created.character_id,),
            ).fetchone()[0],
            0,
        )

    def test_duplicate_character_creation_is_rejected(self):
        self.service.create(self.owner_token, "Alice")
        with self.assertRaises(CharacterAlreadyExists):
            self.service.create(self.owner_token, "Second")
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM characters WHERE account_id=1").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM wallets").fetchone()[0],
            1,
        )

    def test_foreign_and_unknown_character_ids_share_one_error(self):
        created = self.service.create(self.owner_token, "Alice")
        messages = []
        for character_id in (created.character_id, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.get(self.other_token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])
        self.assertEqual(self.service.list_for_account(self.other_token), ())

    def test_expired_and_revoked_sessions_cannot_create_or_list(self):
        self.now[0] += 30
        with self.assertRaises(SessionError):
            self.service.create(self.owner_token, "Alice")
        with self.assertRaises(SessionError):
            self.service.list_for_account(self.owner_token)

        fresh = self.service.sessions.issue(1)
        self.assertTrue(self.service.sessions.revoke(fresh))
        with self.assertRaises(SessionError):
            self.service.create(fresh, "Alice")

    def test_invalid_names_are_rejected_without_database_changes(self):
        for name in ("", " Alice", "Alice ", "\x00", "x" * 65, None, True):
            with self.subTest(name=repr(name)), self.assertRaises(ValueError):
                self.service.create(self.owner_token, name)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM characters").fetchone()[0], 0
        )

    def test_invalid_default_map_id_is_rejected(self):
        for map_id in ("", "map/../x", "map name", "x" * 65, None):
            with self.subTest(map_id=repr(map_id)), self.assertRaises(ValueError):
                SqliteAuthorizedCharacterService(self.db, default_map_id=map_id)

    def test_wallet_failure_rolls_back_character_insert(self):
        self.db.execute(
            """CREATE TRIGGER reject_wallet BEFORE INSERT ON wallets
               BEGIN SELECT RAISE(ABORT, 'wallet unavailable'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.create(self.owner_token, "Alice")
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM characters").fetchone()[0], 0
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM wallets").fetchone()[0], 0
        )

    def test_service_rejects_missing_schema_without_creating_session_tables(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        with self.assertRaisesRegex(ValueError, "schema"):
            SqliteAuthorizedCharacterService(connection)
        self.assertEqual(
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='durable_sessions'"
            ).fetchone()[0],
            0,
        )

    def test_service_requires_unique_and_foreign_key_constraints(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        connection.executescript(
            """CREATE TABLE accounts(id INTEGER PRIMARY KEY, username TEXT);
               CREATE TABLE characters(
                   id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL,
                   name TEXT NOT NULL, map_id TEXT NOT NULL, x INTEGER NOT NULL, y INTEGER NOT NULL
               );
               CREATE TABLE wallets(character_id INTEGER, balance INTEGER);"""
        )
        with self.assertRaisesRegex(ValueError, "unique"):
            SqliteAuthorizedCharacterService(connection)
        self.assertEqual(
            connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='durable_sessions'"
            ).fetchone()[0],
            0,
        )

    def test_concurrent_creation_across_connections_has_one_winner(self):
        worker_count = 6
        barrier = threading.Barrier(worker_count)
        results = []
        errors = []

        def worker():
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                service = SqliteAuthorizedCharacterService(
                    connection, ttl_seconds=30, clock=lambda: self.now[0]
                )
                barrier.wait(timeout=10)
                try:
                    results.append(service.create(self.owner_token, "Alice"))
                except CharacterAlreadyExists:
                    errors.append("duplicate")
            except BaseException as exc:
                errors.append(exc)
            finally:
                connection.close()

        threads = [threading.Thread(target=worker) for _ in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(len(results), 1)
        self.assertEqual(errors, ["duplicate"] * (worker_count - 1))
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM characters WHERE account_id=1").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM wallets").fetchone()[0], 1
        )


if __name__ == "__main__":
    unittest.main()
