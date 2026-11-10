"""Tests for local synthetic credential verification; not APK login tests."""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server.sessions import SessionError
from server.sqlite_account_auth_service import (
    AccountAuthError,
    AccountCredentialAlreadyExists,
    SqliteAccountAuthService,
)


PASSWORD = "correct horse battery staple"


class SqliteAccountAuthServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "accounts.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(
            """CREATE TABLE accounts (
                   id INTEGER PRIMARY KEY,
                   username TEXT NOT NULL UNIQUE
               );
               INSERT INTO accounts(id, username) VALUES (1, 'alice'), (2, 'bob');"""
        )
        self.now = [10_000.0]
        self.service = SqliteAccountAuthService(
            self.db, iterations=100_000, ttl_seconds=30,
            clock=lambda: self.now[0],
        )
        self.addCleanup(self.db.close)

    def test_enrollment_stores_salt_and_digest_not_plaintext(self):
        self.service.enroll_password(1, PASSWORD)
        row = self.db.execute(
            """SELECT algorithm, iterations, salt, password_hash
               FROM account_credentials WHERE account_id = 1"""
        ).fetchone()
        self.assertEqual(row[0], "pbkdf2_sha256")
        self.assertEqual(row[1], 100_000)
        self.assertEqual(len(row[2]), 16)
        self.assertEqual(len(row[3]), 32)
        self.assertNotIn(PASSWORD.encode("utf-8"), Path(self.path).read_bytes())

    def test_valid_credentials_issue_a_resolvable_session(self):
        self.service.enroll_password(1, PASSWORD)
        result = self.service.authenticate_and_issue_session("alice", PASSWORD)
        self.assertEqual(result.account_id, 1)
        self.assertEqual(len(result.token), 43)
        self.assertEqual(self.service.sessions.resolve(result.token), 1)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            1,
        )


    def test_session_token_is_not_in_repr_or_database(self):
        self.service.enroll_password(1, PASSWORD)
        result = self.service.authenticate_and_issue_session("alice", PASSWORD)
        self.assertNotIn(result.token, repr(result))
        self.assertNotIn(result.token.encode("ascii"), Path(self.path).read_bytes())
        stored = self.db.execute(
            "SELECT token_hash FROM durable_sessions"
        ).fetchone()[0]
        self.assertEqual(len(stored), 32)

    def test_wrong_password_and_unknown_username_share_generic_error(self):
        self.service.enroll_password(1, PASSWORD)
        messages = []
        for username, password in (
            ("alice", "incorrect password"),
            ("missing-user", PASSWORD),
            ("bob", PASSWORD),
        ):
            with self.subTest(username=username):
                with self.assertRaises(AccountAuthError) as caught:
                    self.service.authenticate_and_issue_session(username, password)
                messages.append(str(caught.exception))
        self.assertEqual(messages, ["invalid credentials"] * 3)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_duplicate_enrollment_is_rejected_without_replacing_hash(self):
        self.service.enroll_password(1, PASSWORD)
        before = self.db.execute(
            "SELECT salt, password_hash FROM account_credentials WHERE account_id=1"
        ).fetchone()
        with self.assertRaises(AccountCredentialAlreadyExists):
            self.service.enroll_password(1, "a different long password")
        after = self.db.execute(
            "SELECT salt, password_hash FROM account_credentials WHERE account_id=1"
        ).fetchone()
        self.assertEqual(after, before)

    def test_password_policy_and_account_id_are_strict(self):
        for value in ("short", "", "x" * 1025, None, True):
            with self.subTest(password=repr(value)), self.assertRaises(ValueError):
                self.service.enroll_password(1, value)
        for value in (True, 0, -1, "1"):
            with self.subTest(account_id=value), self.assertRaises(ValueError):
                self.service.enroll_password(value, PASSWORD)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM account_credentials").fetchone()[0],
            0,
        )

    def test_unknown_account_cannot_enroll_credentials(self):
        with self.assertRaises(KeyError):
            self.service.enroll_password(999, PASSWORD)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM account_credentials").fetchone()[0],
            0,
        )

    def test_username_validation_fails_closed(self):
        self.service.enroll_password(1, PASSWORD)
        for username in ("", " alice", "alice ", "bad\x00name", None, True):
            with self.subTest(username=repr(username)), self.assertRaises(AccountAuthError):
                self.service.authenticate_and_issue_session(username, PASSWORD)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_credential_change_between_verification_and_issue_is_rejected(self):
        self.service.enroll_password(1, PASSWORD)
        original_lookup = self.service._lookup_credential
        calls = [0]

        def rotate_after_first_read(username):
            row = original_lookup(username)
            calls[0] += 1
            if calls[0] == 1:
                self.db.execute(
                    "UPDATE account_credentials SET password_hash=? WHERE account_id=1",
                    (b"z" * 32,),
                )
            return row

        self.service._lookup_credential = rotate_after_first_read
        with self.assertRaises(AccountAuthError):
            self.service.authenticate_and_issue_session("alice", PASSWORD)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM durable_sessions").fetchone()[0],
            0,
        )

    def test_issued_session_expires_at_the_configured_boundary(self):
        self.service.enroll_password(1, PASSWORD)
        result = self.service.authenticate_and_issue_session("alice", PASSWORD)
        self.now[0] += 30
        with self.assertRaisesRegex(SessionError, "expired"):
            self.service.sessions.resolve(result.token)

    def test_constructor_rejects_missing_account_schema_without_side_effects(self):
        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        with self.assertRaisesRegex(ValueError, "accounts"):
            SqliteAccountAuthService(connection, iterations=100_000)
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertEqual(tables, set())

    def test_iteration_configuration_is_bounded(self):
        for iterations in (True, 0, 99_999, 2_000_001, 100_000.0):
            with self.subTest(iterations=iterations), self.assertRaises(ValueError):
                SqliteAccountAuthService(self.db, iterations=iterations)


if __name__ == "__main__":
    unittest.main()
