"""Integration tests for optional synthetic auth throttling."""
import os
import sqlite3
import tempfile
import unittest

from server.sqlite_account_auth_service import (
    AccountAuthError,
    SqliteAccountAuthService,
)
from server.sqlite_auth_rate_limiter import (
    AuthenticationRateLimited,
    SqliteAuthRateLimiter,
)


PASSWORD = "correct horse battery staple"


class AccountAuthRateLimiterIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "accounts.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(
            """CREATE TABLE accounts (
                   id INTEGER PRIMARY KEY,
                   username TEXT NOT NULL UNIQUE
               );
               INSERT INTO accounts(id, username) VALUES (1, 'alice');"""
        )
        self.now = [10_000.0]
        self.limiter = SqliteAuthRateLimiter(
            self.db, b"stable-test-rate-limit-secret-32-bytes",
            max_attempts=2, window_seconds=60, lockout_seconds=30,
            clock=lambda: self.now[0],
        )
        self.service = SqliteAccountAuthService(
            self.db, iterations=100_000, ttl_seconds=30,
            clock=lambda: self.now[0], rate_limiter=self.limiter,
        )
        self.service.enroll_password(1, PASSWORD)

    def test_failed_attempts_trigger_lockout_and_success_clears_it(self):
        for _ in range(2):
            with self.assertRaises(AccountAuthError):
                self.service.authenticate_and_issue_session("alice", "wrong password")
        with self.assertRaises(AuthenticationRateLimited):
            self.service.authenticate_and_issue_session("alice", PASSWORD)

        self.now[0] += 30
        result = self.service.authenticate_and_issue_session("alice", PASSWORD)
        self.assertEqual(self.service.sessions.resolve(result.token), 1)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            0,
        )

    def test_unknown_username_and_wrong_password_share_limiter_semantics(self):
        for username in ("missing-user", "alice"):
            with self.assertRaises(AccountAuthError) as caught:
                self.service.authenticate_and_issue_session(username, "wrong password")
            self.assertEqual(str(caught.exception), "invalid credentials")
        with self.assertRaises(AuthenticationRateLimited):
            self.service.authenticate_and_issue_session("alice", PASSWORD)

    def test_success_resets_prior_failures(self):
        with self.assertRaises(AccountAuthError):
            self.service.authenticate_and_issue_session("alice", "wrong password")
        self.service.authenticate_and_issue_session("alice", PASSWORD)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM auth_attempt_limits").fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
