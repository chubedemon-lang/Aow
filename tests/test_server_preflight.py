import json
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from server.mock import Domain
from server.runtime_safety import RuntimeSafetyError, validate_loopback_bind
from tools.server_preflight import (
    PreflightError,
    inspect_synthetic_database,
    main,
    run_preflight,
)


class LoopbackBindTests(unittest.TestCase):
    def test_accepts_ipv4_loopback_and_valid_ports(self):
        self.assertEqual(validate_loopback_bind("127.0.0.1", 8765), ("127.0.0.1", 8765))
        self.assertEqual(validate_loopback_bind("127.255.255.254", 65535), ("127.255.255.254", 65535))
        self.assertEqual(validate_loopback_bind("127.0.0.1", 1), ("127.0.0.1", 1))

    def test_rejects_non_loopback_and_hostname_binds(self):
        for host in ("0.0.0.0", "192.168.1.10", "8.8.8.8", "localhost", "::1", "", " 127.0.0.1", None):
            with self.subTest(host=host):
                with self.assertRaises(RuntimeSafetyError):
                    validate_loopback_bind(host, 8765)

    def test_rejects_invalid_ports_and_boolean(self):
        for port in (0, -1, 65536, True, False, 8765.0, "8765", None):
            with self.subTest(port=port):
                with self.assertRaises(RuntimeSafetyError):
                    validate_loopback_bind("127.0.0.1", port)


class SyntheticDatabasePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "mock.sqlite3"
        Domain(self.database)

    def _create_schema_variant(
        self, path, *, unique=True, foreign_keys=True, checks=True, quantity_type="INTEGER"
    ):
        unique_clause = " UNIQUE" if unique else ""
        character_fk = (
            ", FOREIGN KEY(account_id) REFERENCES accounts(id)"
            if foreign_keys else ""
        )
        wallet_fk = (
            ", FOREIGN KEY(character_id) REFERENCES characters(id)"
            if foreign_keys else ""
        )
        inventory_fk = (
            ", FOREIGN KEY(character_id) REFERENCES characters(id)"
            if foreign_keys else ""
        )
        balance_check = " CHECK(balance >= 0)" if checks else ""
        price_check = " CHECK(price > 0)" if checks else ""
        enabled_check = " CHECK(enabled IN (0,1))" if checks else ""
        quantity_check = " CHECK(quantity >= 0)" if checks else ""
        with sqlite3.connect(path) as connection:
            connection.executescript(
                """
                CREATE TABLE accounts (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL%s
                );
                CREATE TABLE characters (
                    id INTEGER PRIMARY KEY,
                    account_id INTEGER NOT NULL%s,
                    name TEXT NOT NULL,
                    map_id TEXT NOT NULL DEFAULT 'test_map',
                    x INTEGER NOT NULL DEFAULT 0,
                    y INTEGER NOT NULL DEFAULT 0%s
                );
                CREATE TABLE wallets (
                    character_id INTEGER PRIMARY KEY,
                    balance INTEGER NOT NULL DEFAULT 0%s%s
                );
                CREATE TABLE shop_catalog (
                    item_id TEXT PRIMARY KEY,
                    price INTEGER NOT NULL%s,
                    enabled INTEGER NOT NULL DEFAULT 1%s
                );
                CREATE TABLE inventory (
                    character_id INTEGER NOT NULL,
                    item_id TEXT NOT NULL,
                    quantity %s NOT NULL%s,
                    PRIMARY KEY(character_id, item_id)%s
                );
                """ % (
                    unique_clause, unique_clause, character_fk, balance_check,
                    wallet_fk, price_check, enabled_check, quantity_type,
                    quantity_check, inventory_fk,
                )
            )

    def test_rejects_same_column_names_without_unique_constraints(self):
        database = Path(self.temp.name) / "missing_unique.sqlite3"
        self._create_schema_variant(database, unique=False)
        with self.assertRaisesRegex(PreflightError, "unique constraints"):
            inspect_synthetic_database(database)

    def test_rejects_missing_foreign_key_constraints(self):
        database = Path(self.temp.name) / "missing_foreign_keys.sqlite3"
        self._create_schema_variant(database, foreign_keys=False)
        with self.assertRaisesRegex(PreflightError, "foreign-key constraints"):
            inspect_synthetic_database(database)

    def test_rejects_missing_check_constraints(self):
        database = Path(self.temp.name) / "missing_checks.sqlite3"
        self._create_schema_variant(database, checks=False)
        with self.assertRaisesRegex(PreflightError, "CHECK constraints"):
            inspect_synthetic_database(database)

    def test_rejects_wrong_required_column_affinity(self):
        database = Path(self.temp.name) / "wrong_type.sqlite3"
        self._create_schema_variant(database, quantity_type="TEXT")
        with self.assertRaisesRegex(PreflightError, "column definitions"):
            inspect_synthetic_database(database)

    def test_valid_database_passes_read_only_preflight(self):
        result = run_preflight("127.0.0.1", 8765, self.database)
        self.assertEqual(result["status"], "ready_for_local_synthetic_testing")
        self.assertEqual(result["sqlite_integrity"], "ok")
        self.assertEqual(result["foreign_key_violations"], 0)
        self.assertTrue(result["schema_valid"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["production_ready"])

    def test_database_inspection_does_not_create_or_mutate_schema(self):
        before = self.database.read_bytes()
        inspect_synthetic_database(self.database)
        self.assertEqual(self.database.read_bytes(), before)

    def test_rejects_missing_database(self):
        with self.assertRaises(PreflightError):
            inspect_synthetic_database(Path(self.temp.name) / "missing.sqlite3")

    def test_rejects_memory_database(self):
        with self.assertRaises(PreflightError):
            inspect_synthetic_database(":memory:")

    def test_rejects_directory_as_database(self):
        with self.assertRaises(PreflightError):
            inspect_synthetic_database(self.temp.name)

    def test_rejects_database_with_missing_tables(self):
        broken = Path(self.temp.name) / "empty.sqlite3"
        sqlite3.connect(broken).close()
        with self.assertRaises(PreflightError):
            inspect_synthetic_database(broken)

    def test_rejects_corrupt_sqlite_file(self):
        broken = Path(self.temp.name) / "corrupt.sqlite3"
        broken.write_bytes(b"not a sqlite database")
        with self.assertRaises(PreflightError):
            inspect_synthetic_database(broken)

    def test_rejects_symlink_database(self):
        link = Path(self.temp.name) / "linked.sqlite3"
        try:
            link.symlink_to(self.database)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks are unavailable in this environment")
        with self.assertRaisesRegex(PreflightError, "symlinks"):
            inspect_synthetic_database(link)

    def test_cli_reports_blocked_without_opening_database_for_public_bind(self):
        output = StringIO()
        missing = Path(self.temp.name) / "must-not-be-created.sqlite3"
        with redirect_stdout(output):
            code = main(["--host", "0.0.0.0", "--db", str(missing)])
        self.assertEqual(code, 2)
        self.assertFalse(missing.exists())
        self.assertEqual(json.loads(output.getvalue())["status"], "blocked")

    def test_rejects_foreign_key_violations(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            connection.execute(
                "INSERT INTO characters(account_id, name) VALUES (999, 'orphan')"
            )
        with self.assertRaisesRegex(PreflightError, "foreign-key"):
            inspect_synthetic_database(self.database)

    def test_rejects_non_loopback_before_database_inspection(self):
        with self.assertRaises(RuntimeSafetyError):
            run_preflight("0.0.0.0", 8765, self.database)


if __name__ == "__main__":
    unittest.main()
