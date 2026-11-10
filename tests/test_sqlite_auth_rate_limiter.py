"""Tests for persistent synthetic authentication throttling."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sqlite_auth_rate_limiter import (
    AuthenticationRateLimited,
    SqliteAuthRateLimiter,
)


class SqliteAuthRateLimiterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "auth.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(self.db.close)
        self.now = [1_000.0]
        self.secret = b"r" * 32
        self.limiter = SqliteAuthRateLimiter(
            self.db, self.secret, max_attempts=3, window_seconds=60,
            lockout_seconds=30, clock=lambda: self.now[0],
        )

    def test_lockout_starts_at_threshold_and_expires_at_exact_boundary(self):
        self.assertEqual(self.limiter.record_failure("alice"), 1)
        self.assertEqual(self.limiter.record_failure("alice"), 2)
        self.limiter.check_allowed("alice")
        self.assertEqual(self.limiter.record_failure("alice"), 3)
        with self.assertRaises(AuthenticationRateLimited):
            self.limiter.check_allowed("alice")
        self.now[0] = 1_029.999
        with self.assertRaises(AuthenticationRateLimited):
            self.limiter.check_allowed("alice")
        self.now[0] = 1_030.0
        self.limiter.check_allowed("alice")
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            0,
        )

    def test_failure_window_expires_before_threshold(self):
        self.assertEqual(self.limiter.record_failure("alice"), 1)
        self.assertEqual(self.limiter.record_failure("alice"), 2)
        self.now[0] += 60
        self.limiter.check_allowed("alice")
        self.assertEqual(self.limiter.record_failure("alice"), 1)

    def test_success_clears_failure_bucket(self):
        self.limiter.record_failure("alice")
        self.limiter.record_failure("alice")
        self.limiter.record_success("alice")
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            0,
        )
        self.limiter.check_allowed("alice")

    def test_only_keyed_digest_is_persisted(self):
        principal = "private-user-name-not-for-storage"
        self.limiter.record_failure(principal)
        raw = open(self.path, "rb").read()
        self.assertNotIn(principal.encode("utf-8"), raw)
        digest = self.db.execute(
            "SELECT principal_digest FROM auth_attempt_limits"
        ).fetchone()[0]
        self.assertEqual(len(digest), 32)
        self.assertNotEqual(digest, principal.encode("utf-8"))

    def test_invalid_principals_share_one_bounded_bucket(self):
        self.limiter.record_failure(None)
        self.limiter.record_failure(object())
        with self.assertRaises(AuthenticationRateLimited):
            self.limiter.record_failure("\x00bad")

    def test_transaction_helpers_leave_commit_and_rollback_to_caller(self):
        self.db.execute("BEGIN IMMEDIATE")
        self.limiter.record_failure_in_transaction("alice")
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            0,
        )

        self.db.execute("BEGIN IMMEDIATE")
        self.limiter.record_failure_in_transaction("alice")
        self.db.commit()

        self.db.execute("BEGIN IMMEDIATE")
        self.limiter.record_success_in_transaction("alice")
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            1,
        )

        self.db.execute("BEGIN IMMEDIATE")
        self.limiter.record_success_in_transaction("alice")
        self.db.commit()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            0,
        )

    def test_transaction_helpers_require_caller_transaction(self):
        with self.assertRaisesRegex(ValueError, "transaction"):
            self.limiter.record_failure_in_transaction("alice")
        with self.assertRaisesRegex(ValueError, "transaction"):
            self.limiter.record_success_in_transaction("alice")

    def test_rejects_invalid_configuration(self):
        for secret in (b"short", "s" * 32, bytearray(b"s" * 32), None):
            with self.subTest(secret=type(secret).__name__), self.assertRaises(ValueError):
                SqliteAuthRateLimiter(self.db, secret)
        for kwargs in (
            {"max_attempts": True},
            {"max_attempts": 0},
            {"window_seconds": 0},
            {"window_seconds": 86_401},
            {"lockout_seconds": -1},
            {"lockout_seconds": True},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SqliteAuthRateLimiter(self.db, self.secret, **kwargs)

    def test_concurrent_failures_are_serialized_across_connections(self):
        worker_count = 8
        barrier = threading.Barrier(worker_count)
        errors = []

        def worker():
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                limiter = SqliteAuthRateLimiter(
                    connection, self.secret, max_attempts=3,
                    window_seconds=60, lockout_seconds=30,
                    clock=lambda: self.now[0],
                )
                limiter.check_allowed("alice")
                barrier.wait(timeout=10)
                limiter.record_failure("alice")
            except BaseException as exc:
                errors.append(exc)
            finally:
                connection.close()

        threads = [threading.Thread(target=worker) for _ in range(worker_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=15)

        self.assertFalse(errors, repr(errors))
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        row = self.db.execute(
            """SELECT attempt_count, blocked_until
               FROM auth_attempt_limits"""
        ).fetchone()
        self.assertEqual(row[0], 3)
        self.assertEqual(row[1], 1_030.0)


if __name__ == "__main__":
    unittest.main()
