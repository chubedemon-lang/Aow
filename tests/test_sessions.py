"""Tests for synthetic session isolation, not APK protocol."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server.mock import Domain
from server.sessions import SessionError, SessionManager


class HostileToken(str):
    def __hash__(self):
        raise AssertionError("custom token hash must not run")

    def encode(self, *args, **kwargs):
        raise AssertionError("custom token encode must not run")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.domain = Domain(Path(self.tmp.name) / "state.sqlite3")
        self.now = 100.0
        self.sessions = SessionManager(ttl_seconds=10, clock=lambda: self.now)

    def test_ownership_and_isolation(self):
        alice = self.domain.create_character("alice", "Alice")["id"]
        bob = self.domain.create_character("bob", "Bob")["id"]
        with self.domain.connection() as db:
            alice_account = db.execute("SELECT account_id FROM characters WHERE id=?", (alice,)).fetchone()[0]
            bob_account = db.execute("SELECT account_id FROM characters WHERE id=?", (bob,)).fetchone()[0]
        token = self.sessions.issue(alice_account)
        other = self.sessions.issue(bob_account)
        self.assertEqual(self.sessions.require_character(token, alice, self.domain), alice)
        with self.assertRaises(SessionError):
            self.sessions.require_character(token, bob, self.domain)
        with self.assertRaises(SessionError):
            self.sessions.require_character(other, alice, self.domain)
        with self.assertRaises(SessionError):
            self.sessions.require_character("forged", alice, self.domain)

    def test_require_character_closes_connection_on_success_and_rejection(self):
        alice = self.domain.create_character("alice", "Alice")["id"]
        bob = self.domain.create_character("bob", "Bob")["id"]
        with self.domain.connection() as db:
            alice_account = db.execute(
                "SELECT account_id FROM characters WHERE id=?", (alice,)
            ).fetchone()[0]

        token = self.sessions.issue(alice_account)
        original_connect = self.domain.connect
        opened = []

        def tracked_connect():
            connection = original_connect()
            opened.append(connection)
            return connection

        self.domain.connect = tracked_connect
        self.assertEqual(
            self.sessions.require_character(token, alice, self.domain), alice
        )
        with self.assertRaises(SessionError):
            self.sessions.require_character(token, bob, self.domain)

        self.assertEqual(len(opened), 2)
        for connection in opened:
            with self.subTest(connection=connection):
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute("SELECT 1")

    def test_expiry_revoke_and_purge(self):
        token = self.sessions.issue(1)
        self.assertEqual(self.sessions.resolve(token), 1)
        self.now = 110.0
        with self.assertRaises(SessionError):
            self.sessions.resolve(token)
        token = self.sessions.issue(1)
        self.sessions.revoke(token)
        with self.assertRaises(SessionError):
            self.sessions.resolve(token)
        self.sessions.issue(2)
        self.now = 121.0
        self.assertEqual(self.sessions.purge_expired(), 1)

    def test_input_validation(self):
        for value in (True, 0, -1, "1"):
            with self.assertRaises(ValueError):
                self.sessions.issue(value)
        with self.assertRaises(ValueError):
            SessionManager(ttl_seconds=0)
        with self.assertRaises(SessionError):
            self.sessions.resolve(None)
        token = self.sessions.issue(1)
        for value in (True, 0, "1"):
            with self.assertRaises(SessionError):
                self.sessions.require_character(token, value, self.domain)

    def test_rejects_str_subclasses_before_hash_or_encode_hooks(self):
        token = self.sessions.issue(9)
        hostile = HostileToken(token)

        with self.assertRaises(SessionError):
            self.sessions.resolve(hostile)
        # Revoke preserves its historical no-op behavior for invalid tokens.
        self.sessions.revoke(hostile)
        self.assertEqual(self.sessions.resolve(token), 9)

    def test_clock_must_be_callable(self):
        with self.assertRaisesRegex(ValueError, "clock must be callable"):
            SessionManager(clock=123)

    def test_issue_rejects_invalid_clock_values_without_creating_sessions(self):
        class HostileInt(int):
            def __float__(self):
                raise AssertionError("custom numeric conversion must not run")

        class HostileFloat(float):
            def __float__(self):
                raise AssertionError("custom numeric conversion must not run")

        invalid_values = (
            True, -1, float("nan"), float("inf"), float("-inf"), "100",
            HostileInt(100), HostileFloat(100.0),
        )
        for value in invalid_values:
            with self.subTest(value_type=type(value).__name__, value=str(value)):
                manager = SessionManager(clock=lambda value=value: value)
                with self.assertRaises(SessionError):
                    manager.issue(1)
                self.assertEqual(manager._sessions, {})

    def test_clock_exception_fails_closed_without_consuming_session(self):
        token = self.sessions.issue(7)

        def broken_clock():
            raise RuntimeError("private clock detail")

        self.sessions.clock = broken_clock
        with self.assertRaisesRegex(SessionError, "session clock failed"):
            self.sessions.resolve(token)

        self.sessions.clock = lambda: self.now
        self.assertEqual(self.sessions.resolve(token), 7)

    def test_clock_rollback_cannot_extend_or_purge_sessions(self):
        token = self.sessions.issue(8)
        self.now = 99.0

        with self.assertRaisesRegex(SessionError, "moved backwards"):
            self.sessions.resolve(token)
        with self.assertRaisesRegex(SessionError, "moved backwards"):
            self.sessions.purge_expired()
        self.assertEqual(len(self.sessions._sessions), 1)

        self.now = 100.0
        self.assertEqual(self.sessions.resolve(token), 8)

    def test_unrepresentable_expiry_does_not_issue_a_token(self):
        manager = SessionManager(
            ttl_seconds=10 ** 400,
            clock=lambda: 1.0,
        )
        with self.assertRaisesRegex(SessionError, "expiry is not representable"):
            manager.issue(9)
        self.assertEqual(manager._sessions, {})


if __name__ == "__main__":
    unittest.main()
