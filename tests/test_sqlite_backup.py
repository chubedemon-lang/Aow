"""Tests for the verified, non-overwriting SQLite backup utility."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tools.sqlite_backup import BackupError, create_backup


def make_database(path, *, foreign_key_violation=False):
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys = OFF" if foreign_key_violation
                           else "PRAGMA foreign_keys = ON")
        connection.executescript(
            """CREATE TABLE accounts (
                   id INTEGER PRIMARY KEY,
                   username TEXT NOT NULL UNIQUE
               );
               CREATE TABLE characters (
                   id INTEGER PRIMARY KEY,
                   account_id INTEGER NOT NULL,
                   name TEXT NOT NULL,
                   FOREIGN KEY(account_id) REFERENCES accounts(id)
               );
               INSERT INTO accounts(id, username) VALUES (1, 'alice');"""
        )
        if foreign_key_violation:
            connection.execute(
                "INSERT INTO characters(id, account_id, name) VALUES (1, 999, 'orphan')"
            )
        else:
            connection.execute(
                "INSERT INTO characters(id, account_id, name) VALUES (1, 1, 'hero')"
            )
        connection.commit()
    finally:
        connection.close()


class SqliteBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.sqlite3"
        self.destination = self.root / "backup.sqlite3"
        make_database(self.source)

    def test_creates_verified_backup_without_changing_source(self):
        source_before = self.source.read_bytes()
        report = create_backup(self.source, self.destination)
        self.assertEqual(self.source.read_bytes(), source_before)
        self.assertEqual(report.integrity, "ok")
        self.assertEqual(report.foreign_key_violations, 0)
        self.assertGreaterEqual(report.page_count, 1)
        self.assertEqual(report.tables, ("accounts", "characters"))
        self.assertEqual(report.destination, str(self.destination))

        connection = sqlite3.connect(self.destination)
        try:
            self.assertEqual(
                connection.execute("SELECT name FROM characters").fetchone(),
                ("hero",),
            )
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchall(),
                             [("ok",)])
        finally:
            connection.close()

    def test_includes_committed_wal_content(self):
        wal_source = self.root / "wal-source.sqlite3"
        connection = sqlite3.connect(wal_source)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, value TEXT)")
            connection.execute("INSERT INTO events(value) VALUES ('committed-in-wal')")
            connection.commit()
            wal_destination = self.root / "wal-backup.sqlite3"
            report = create_backup(wal_source, wal_destination)
            self.assertIn("events", report.tables)
            copied = sqlite3.connect(wal_destination)
            try:
                self.assertEqual(
                    copied.execute("SELECT value FROM events").fetchone(),
                    ("committed-in-wal",),
                )
            finally:
                copied.close()
        finally:
            connection.close()

    def test_refuses_to_overwrite_existing_destination(self):
        self.destination.write_bytes(b"keep-existing-file")
        with self.assertRaises(BackupError):
            create_backup(self.source, self.destination)
        self.assertEqual(self.destination.read_bytes(), b"keep-existing-file")

    def test_refuses_source_equal_to_destination(self):
        with self.assertRaises(BackupError):
            create_backup(self.source, self.source)
        self.assertTrue(self.source.is_file())

    def test_rejects_missing_directory_and_memory_sources(self):
        for source in (
            self.root / "missing.sqlite3",
            self.root,
            ":memory:",
        ):
            with self.subTest(source=str(source)):
                with self.assertRaises(BackupError):
                    create_backup(source, self.destination)

    def test_rejects_symlink_source(self):
        link = self.root / "source-link.sqlite3"
        try:
            link.symlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(BackupError):
            create_backup(link, self.destination)

    def test_rejects_symlink_destination(self):
        link = self.root / "backup-link.sqlite3"
        try:
            link.symlink_to(self.source)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable on this platform")
        with self.assertRaises(BackupError):
            create_backup(self.source, link)
        self.assertTrue(self.source.is_file())

    def test_rejects_foreign_key_corruption_and_cleans_temporary_file(self):
        broken = self.root / "broken.sqlite3"
        make_database(broken, foreign_key_violation=True)
        destination = self.root / "must-not-publish.sqlite3"
        with self.assertRaises(BackupError):
            create_backup(broken, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.glob(".must-not-publish.sqlite3.*.tmp")), [])

    def test_unicode_destination_path(self):
        destination = self.root / "bản-sao.sqlite3"
        report = create_backup(self.source, destination)
        self.assertTrue(destination.is_file())
        self.assertEqual(report.integrity, "ok")


if __name__ == "__main__":
    unittest.main()
