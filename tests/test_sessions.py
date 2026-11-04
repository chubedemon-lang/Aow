"""Tests for synthetic session isolation, not APK protocol."""
import tempfile
import unittest
from pathlib import Path

from server.mock import Domain
from server.sessions import SessionError, SessionManager


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
        with self.domain.connect() as db:
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


if __name__ == "__main__":
    unittest.main()
