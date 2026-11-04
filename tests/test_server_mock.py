"""Tests for synthetic server domain only; no APK protocol assertions."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server.mock import Domain


class DomainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.domain = Domain(Path(self.temp.name) / "test.sqlite3")

    def test_create_read_move_and_persistence(self):
        created = self.domain.create_character("alice", "hero")
        self.assertEqual(created["x"], 0)
        moved = self.domain.move(created["id"], 25, -10)
        self.assertEqual((moved["x"], moved["y"]), (25, -10))
        reopened = Domain(self.domain.database)
        self.assertEqual(reopened.get_character(created["id"]), moved)

    def test_unique_character_per_account(self):
        self.domain.create_character("alice", "hero")
        with self.assertRaises(sqlite3.IntegrityError):
            self.domain.create_character("alice", "second")

    def test_missing_character(self):
        with self.assertRaises(KeyError):
            self.domain.get_character(999)

    def test_reject_invalid_input(self):
        with self.assertRaises(ValueError):
            self.domain.create_character("", "hero")
        created = self.domain.create_character("alice", "hero")
        for x, y in [(True, 1), (1.5, 2), (10001, 0)]:
            with self.assertRaises(ValueError):
                self.domain.move(created["id"], x, y)


if __name__ == "__main__":
    unittest.main()
