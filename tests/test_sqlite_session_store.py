"""Regression tests for durable synthetic sessions; not APK login tests."""
import hashlib
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sessions import SessionError
from server.sqlite_session_store import SqliteSessionStore


class SqliteSessionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "sessions.sqlite3")
        self.now = 1_000.0
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.store = SqliteSessionStore(
            self.db, ttl_seconds=60, clock=lambda: self.now
        )
        self.addCleanup(self.db.close)

    def test_issue_resolve_and_store_only_digest(self):
        token = self.store.issue(42)
        self.assertEqual(len(token), 43)
        self.assertEqual(self.store.resolve(token), 42)
        row = self.db.execute(
            "SELECT token_hash, account_id FROM durable_sessions"
        ).fetchone()
        self.assertEqual(row[0], hashlib.sha256(token.encode("ascii")).digest())
        self.assertNotEqual(row[0], token.encode("ascii"))
        self.assertEqual(row[1], 42)

    def test_expiry_is_enforced_at_exact_boundary(self):
        token = self.store.issue(7)
        self.now += 60
        with self.assertRaisesRegex(SessionError, "expired"):
            self.store.resolve(token)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_purge_expired_keeps_active_sessions(self):
        expired = self.store.issue(1, ttl_seconds=2)
        active = self.store.issue(2, ttl_seconds=20)
        self.now += 2
        self.assertEqual(self.store.purge_expired(), 1)
        self.assertEqual(self.store.resolve(active), 2)
        with self.assertRaises(SessionError):
            self.store.resolve(expired)

    def test_resolve_in_transaction_requires_caller_transaction(self):
        token = self.store.issue(77)
        with self.assertRaisesRegex(ValueError, "transaction"):
            self.store.resolve_in_transaction(token)

        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.assertEqual(self.store.resolve_in_transaction(token), 77)
            self.assertTrue(self.db.in_transaction)
        finally:
            self.db.rollback()

    def test_resolve_in_transaction_rejects_expired_and_revoked_tokens(self):
        expired = self.store.issue(78, ttl_seconds=2)
        revoked = self.store.issue(79)
        self.assertTrue(self.store.revoke(revoked))
        self.now += 2

        self.db.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(SessionError, "expired"):
                self.store.resolve_in_transaction(expired)
            with self.assertRaisesRegex(SessionError, "invalid"):
                self.store.resolve_in_transaction(revoked)
            self.assertTrue(self.db.in_transaction)
        finally:
            self.db.rollback()

    def test_revoke_is_idempotent(self):
        token = self.store.issue(9)
        self.assertTrue(self.store.revoke(token))
        self.assertFalse(self.store.revoke(token))
        with self.assertRaises(SessionError):
            self.store.resolve(token)

    def test_session_survives_store_reopen(self):
        token = self.store.issue(12)
        self.db.close()
        reopened = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(reopened.close)
        store = SqliteSessionStore(reopened, ttl_seconds=60, clock=lambda: self.now)
        self.assertEqual(store.resolve(token), 12)

    def test_invalid_inputs_do_not_create_rows(self):
        for account_id in (True, 0, -1, "1", 2**63):
            with self.subTest(account_id=account_id), self.assertRaises(ValueError):
                self.store.issue(account_id)
        for ttl in (True, 0, -1, 31_536_001, 1.5):
            with self.subTest(ttl=ttl), self.assertRaises(ValueError):
                self.store.issue(1, ttl_seconds=ttl)
        for token in (None, "", "x" * 43, "not.a.token", "é" * 43):
            with self.subTest(token=token), self.assertRaises(SessionError):
                self.store.resolve(token)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_clock_must_be_finite_epoch_value(self):
        for value in (True, -1, float("nan"), float("inf"), "100", 10**1000):
            store = SqliteSessionStore(self.db, clock=lambda value=value: value)
            with self.subTest(value=str(value)[:20]), self.assertRaises(ValueError):
                store.issue(1)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_constructor_does_not_commit_callers_transaction(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (1)")
        with self.assertRaises(ValueError):
            SqliteSessionStore(self.db)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM caller_work").fetchone()[0],
            0,
        )

    def test_concurrent_revoke_has_one_winner(self):
        token = self.store.issue(33)
        barrier = threading.Barrier(8)

        def revoke_once():
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                store = SqliteSessionStore(
                    connection, ttl_seconds=60, clock=lambda: self.now
                )
                barrier.wait(timeout=5)
                return store.revoke(token)
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: revoke_once(), range(8)))
        self.assertEqual(sum(results), 1)
        with self.assertRaises(SessionError):
            self.store.resolve(token)


if __name__ == "__main__":
    unittest.main()
