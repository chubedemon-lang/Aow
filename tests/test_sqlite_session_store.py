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

    def test_purge_expired_supports_repeatable_bounded_batches(self):
        oldest = self.store.issue(10, ttl_seconds=1)
        middle = self.store.issue(11, ttl_seconds=2)
        newest = self.store.issue(12, ttl_seconds=3)
        active = self.store.issue(13, ttl_seconds=20)
        self.now += 3

        self.assertEqual(self.store.purge_expired(batch_size=2), 2)
        remaining = {
            row[0] for row in self.db.execute(
                "SELECT token_hash FROM durable_sessions"
            ).fetchall()
        }
        self.assertEqual(
            remaining,
            {
                hashlib.sha256(newest.encode("ascii")).digest(),
                hashlib.sha256(active.encode("ascii")).digest(),
            },
        )
        self.assertEqual(self.store.purge_expired(batch_size=2), 1)
        self.assertEqual(self.store.resolve(active), 13)
        for token in (oldest, middle, newest):
            with self.subTest(token_digest=hashlib.sha256(token.encode()).hexdigest()[:8]):
                with self.assertRaises(SessionError):
                    self.store.resolve(token)

    def test_purge_expired_rejects_invalid_batch_sizes_without_mutation(self):
        expired = self.store.issue(14, ttl_seconds=1)
        self.now += 1
        for batch_size in (True, 0, -1, 1.5, "1", 10_001):
            with self.subTest(batch_size=batch_size):
                with self.assertRaisesRegex(ValueError, "batch size"):
                    self.store.purge_expired(batch_size=batch_size)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            1,
        )
        self.assertFalse(self.db.in_transaction)
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

    def test_issue_rejects_finite_clock_values_that_cannot_represent_expiry(self):
        for value in (1e20, float.fromhex("0x1.fffffffffffffp+1023")):
            store = SqliteSessionStore(self.db, clock=lambda value=value: value)
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "expiry"):
                store.issue(51)
            self.assertFalse(self.db.in_transaction)
            self.assertEqual(
                self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
                0,
            )

    def test_issue_in_transaction_preserves_caller_transaction_on_unrepresentable_expiry(self):
        self.store.clock = lambda: 1e20
        self.db.execute("BEGIN IMMEDIATE")
        with self.assertRaisesRegex(ValueError, "expiry"):
            self.store.issue_in_transaction(52)
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )
        self.db.rollback()

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


    def test_authorized_transaction_commits_protected_state(self):
        token = self.store.issue(81)
        self.db.execute(
            "CREATE TABLE protected_state (account_id INTEGER NOT NULL, value TEXT NOT NULL)"
        )

        with self.store.authorized_transaction(token) as account_id:
            self.assertEqual(account_id, 81)
            self.db.execute(
                "INSERT INTO protected_state(account_id, value) VALUES (?, ?)",
                (account_id, "committed"),
            )

        self.assertFalse(self.db.in_transaction)
        self.assertEqual(
            self.db.execute("SELECT account_id, value FROM protected_state").fetchone(),
            (81, "committed"),
        )

    def test_authorized_transaction_rolls_back_protected_state_on_error(self):
        token = self.store.issue(82)
        self.db.execute(
            "CREATE TABLE protected_state (account_id INTEGER NOT NULL, value TEXT NOT NULL)"
        )

        with self.assertRaisesRegex(RuntimeError, "abort protected operation"):
            with self.store.authorized_transaction(token) as account_id:
                self.db.execute(
                    "INSERT INTO protected_state(account_id, value) VALUES (?, ?)",
                    (account_id, "must-rollback"),
                )
                raise RuntimeError("abort protected operation")

        self.assertFalse(self.db.in_transaction)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM protected_state").fetchone()[0],
            0,
        )

    def test_authorized_transaction_rejects_expired_or_revoked_tokens(self):
        expired = self.store.issue(83, ttl_seconds=2)
        revoked = self.store.issue(84)
        self.assertTrue(self.store.revoke(revoked))
        self.now += 2

        for token in (expired, revoked):
            with self.subTest(token_hash=hashlib.sha256(token.encode()).hexdigest()[:8]):
                with self.assertRaises(SessionError):
                    with self.store.authorized_transaction(token):
                        self.fail("unauthorized transaction must not yield")
                self.assertFalse(self.db.in_transaction)

    def test_authorized_transaction_does_not_take_over_caller_transaction(self):
        token = self.store.issue(85)
        self.db.execute("CREATE TABLE caller_state (value INTEGER)")
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_state VALUES (1)")

        with self.assertRaisesRegex(ValueError, "active transaction"):
            with self.store.authorized_transaction(token):
                self.fail("must not enter caller-owned transaction")

        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM caller_state").fetchone()[0],
            0,
        )

    def test_authorized_transaction_holds_write_lock_against_revocation(self):
        token = self.store.issue(86)
        second_connection = sqlite3.connect(
            self.path, timeout=10, isolation_level=None
        )
        self.addCleanup(second_connection.close)
        second_store = SqliteSessionStore(
            second_connection, ttl_seconds=60, clock=lambda: self.now
        )
        # Make lock contention fail immediately and deterministically.
        second_connection.execute("PRAGMA busy_timeout = 0")
        self.db.execute(
            "CREATE TABLE protected_state (account_id INTEGER NOT NULL, value TEXT NOT NULL)"
        )

        with self.store.authorized_transaction(token) as account_id:
            self.assertEqual(account_id, 86)
            with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                second_store.revoke(token)
            self.assertTrue(self.db.in_transaction)
            self.db.execute(
                "INSERT INTO protected_state(account_id, value) VALUES (?, ?)",
                (account_id, "authorized-before-revoke"),
            )

        # Once the protected operation commits, revocation can acquire the lock.
        self.assertTrue(second_store.revoke(token))
        self.assertEqual(
            self.db.execute(
                "SELECT value FROM protected_state WHERE account_id=86"
            ).fetchone()[0],
            "authorized-before-revoke",
        )
        with self.assertRaises(SessionError):
            self.store.resolve(token)

    def test_issue_in_transaction_requires_caller_transaction(self):
        with self.assertRaisesRegex(ValueError, "transaction"):
            self.store.issue_in_transaction(44)

    def test_issue_in_transaction_joins_and_respects_caller_rollback(self):
        self.db.execute("BEGIN IMMEDIATE")
        token = self.store.issue_in_transaction(45)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        with self.assertRaises(SessionError):
            self.store.resolve(token)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_issue_in_transaction_is_committed_by_caller(self):
        self.db.execute("BEGIN IMMEDIATE")
        token = self.store.issue_in_transaction(46, ttl_seconds=10)
        self.db.commit()
        self.assertEqual(self.store.resolve(token), 46)


if __name__ == "__main__":
    unittest.main()
