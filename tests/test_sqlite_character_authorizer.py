"""Transactional session-to-character authorization regression tests."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_character_authorizer import SqliteCharacterAuthorizer
from server.sqlite_session_store import SqliteSessionStore


class SqliteCharacterAuthorizerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "auth.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
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
        self.now = [1000.0]
        self.sessions = SqliteSessionStore(
            self.db, ttl_seconds=60, clock=lambda: self.now[0]
        )
        self.authorizer = SqliteCharacterAuthorizer(self.db, self.sessions)
        self.owner_token = self.sessions.issue(1)
        self.other_token = self.sessions.issue(2)

    def test_require_in_transaction_requires_existing_transaction(self):
        with self.assertRaisesRegex(ValueError, "transaction"):
            self.authorizer.require_in_transaction(self.owner_token, 101)

        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.assertEqual(
                self.authorizer.require_in_transaction(self.owner_token, 101),
                "101",
            )
            self.assertTrue(self.db.in_transaction)
        finally:
            self.db.rollback()

    def test_foreign_character_and_invalid_session_are_denied(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaises(SessionError):
                self.authorizer.require_in_transaction(self.other_token, 101)
            with self.assertRaises(SessionError):
                self.authorizer.require_in_transaction(self.owner_token, 202)
            with self.assertRaises(SessionError):
                self.authorizer.require_in_transaction("invalid", 101)
        finally:
            self.db.rollback()

    def test_expired_session_is_denied_inside_transaction(self):
        self.now[0] += 60
        self.db.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(SessionError, "expired"):
                self.authorizer.require_in_transaction(self.owner_token, 101)
            self.assertTrue(self.db.in_transaction)
        finally:
            self.db.rollback()

    def test_revocation_serializes_after_protected_transaction(self):
        connection = sqlite3.connect(
            self.path, timeout=10, isolation_level=None
        )
        self.addCleanup(connection.close)
        revoker = SqliteSessionStore(
            connection, ttl_seconds=60, clock=lambda: self.now[0]
        )
        started = threading.Event()
        completed = threading.Event()
        result = []

        self.db.execute("BEGIN IMMEDIATE")
        self.assertEqual(
            self.authorizer.require_in_transaction(self.owner_token, 101),
            "101",
        )

        def revoke():
            started.set()
            result.append(revoker.revoke(self.owner_token))
            completed.set()

        thread = threading.Thread(target=revoke)
        thread.start()
        self.assertTrue(started.wait(2))
        self.assertFalse(completed.wait(0.05))
        self.db.commit()
        self.assertTrue(completed.wait(5))
        thread.join(timeout=5)
        self.assertEqual(result, [True])
        with self.assertRaises(SessionError):
            self.sessions.resolve(self.owner_token)


if __name__ == "__main__":
    unittest.main()
