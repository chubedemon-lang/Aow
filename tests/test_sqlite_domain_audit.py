"""Regression tests for the read-only synthetic SQLite domain audit."""
import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_map_position_store import SqliteMapPositionStore
from server.sqlite_player_state_store import SqlitePlayerStateStore
from tools.sqlite_domain_audit import (
    DomainAuditError,
    inspect_domain_database,
    main,
)


class SqliteDomainAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "domain.sqlite3"

        connection = sqlite3.connect(self.path, isolation_level=None)
        players = SqlitePlayerStateStore(connection)
        players.create("hero", currency=25)
        players.apply("hero", "earn-1", 0, currency_delta=5)

        inventory = SqliteInventoryStore(connection)
        inventory.create("hero", capacity=8, max_stack=20)
        inventory.apply("hero", "grant-1", 0, [("potion", 3)])

        positions = SqliteMapPositionStore(connection)
        positions.create("hero")
        positions.enter("hero", "enter-1", 0, 7, 10, -4)
        connection.close()

    def test_audits_all_existing_domain_stores(self):
        result = inspect_domain_database(self.path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sqlite_integrity"], "ok")
        self.assertEqual(result["foreign_key_violations"], 0)
        self.assertEqual(
            result["audits"],
            {
                "inventory": {"snapshots": 1, "items": 1, "mutations": 1},
                "player_state": {"snapshots": 1, "mutations": 1},
                "map_position": {"snapshots": 1, "mutations": 1},
            },
        )

    def test_audit_is_read_only_at_file_level(self):
        before = self.path.read_bytes()
        inspect_domain_database(self.path)
        self.assertEqual(self.path.read_bytes(), before)

    def test_no_domain_stores_is_reported_explicitly(self):
        empty = Path(self.temp.name) / "empty.sqlite3"
        sqlite3.connect(empty).close()
        result = inspect_domain_database(empty)
        self.assertEqual(result["status"], "no_domain_stores")
        self.assertEqual(result["audits"], {})

    def test_partial_store_schema_fails_closed(self):
        partial = Path(self.temp.name) / "partial.sqlite3"
        connection = sqlite3.connect(partial)
        connection.execute(
            "CREATE TABLE map_position_snapshots "
            "(character_id TEXT PRIMARY KEY, map_id INTEGER, x INTEGER, "
            "y INTEGER, revision INTEGER)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError, "map_position schema is incomplete"
        ):
            inspect_domain_database(partial)

    def test_corrupt_map_receipt_fails_closed(self):
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE map_position_mutations SET payload_json=? "
            "WHERE request_id='enter-1'",
            (
                '{"operation":"enter","operation":"leave",'
                '"map_id":7,"x":10,"y":-4}',
            ),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError, "map_position integrity audit failed"
        ):
            inspect_domain_database(self.path)

    def test_rejects_corrupt_database_file(self):
        corrupt = Path(self.temp.name) / "corrupt.sqlite3"
        corrupt.write_bytes(b"not a sqlite database")
        with self.assertRaises(DomainAuditError):
            inspect_domain_database(corrupt)

    def test_rejects_missing_database_and_memory_database(self):
        with self.assertRaises(DomainAuditError):
            inspect_domain_database(Path(self.temp.name) / "missing.sqlite3")
        with self.assertRaises(DomainAuditError):
            inspect_domain_database(":memory:")

    def test_rejects_symlink_database(self):
        link = Path(self.temp.name) / "linked.sqlite3"
        try:
            link.symlink_to(self.path)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable in this environment")
        with self.assertRaisesRegex(DomainAuditError, "symlinks"):
            inspect_domain_database(link)

    def test_cli_emits_machine_readable_success(self):
        output = StringIO()
        with redirect_stdout(output):
            code = main(["--db", str(self.path)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "ok")

    def test_cli_fails_without_creating_missing_database(self):
        missing = Path(self.temp.name) / "must-not-exist.sqlite3"
        output = StringIO()
        with redirect_stdout(output):
            code = main(["--db", str(missing)])
        self.assertEqual(code, 2)
        self.assertFalse(missing.exists())
        self.assertEqual(json.loads(output.getvalue())["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
