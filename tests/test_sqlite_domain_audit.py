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
from server.sqlite_quest_inventory_award_store import SqliteQuestInventoryAwardStore
from server.sqlite_reward_ledger import SqliteRewardLedger
from server.sqlite_shop_store import ShopOffer, SqliteShopStore
from tools.sqlite_domain_audit import (
    DomainAuditError,
    _open_read_only,
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
        awards = SqliteQuestInventoryAwardStore(connection, inventory)
        awards.grant_once("hero", "quest-award-1", 1, 7, "gem", 2)

        positions = SqliteMapPositionStore(connection)
        positions.create("hero")
        positions.enter("hero", "enter-1", 0, 7, 10, -4)

        rewards = SqliteRewardLedger(connection)
        rewards.grant_once("reward-1", "hero", 7, "gem", 2)

        shop = SqliteShopStore(
            connection,
            {"potion-pack": ShopOffer("potion-pack", "potion", 3)},
        )
        shop.purchase(
            "hero", "shop-purchase-1",
            expected_player_revision=1,
            expected_inventory_revision=2,
            offer_id="potion-pack",
            quantity=2,
        )
        connection.close()

    def test_read_only_connection_enables_foreign_keys_before_query_only(self):
        connection = _open_read_only(self.path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA foreign_keys").fetchone(), (1,)
            )
            self.assertEqual(
                connection.execute("PRAGMA query_only").fetchone(), (1,)
            )
        finally:
            connection.close()

    def test_audits_all_existing_domain_stores(self):
        result = inspect_domain_database(self.path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["sqlite_integrity"], "ok")
        self.assertEqual(result["foreign_key_violations"], 0)
        self.assertEqual(
            result["audits"],
            {
                "inventory": {
                    "snapshots": 1,
                    "items": 2,
                    "mutations": 3,
                    "anchored_snapshots": 1,
                    "legacy_unanchored_snapshots": 0,
                },
                "quest_inventory_awards": {
                    "awards": 1,
                    "linked_inventory_mutations": 1,
                },
                "player_state": {
                    "snapshots": 1,
                    "mutations": 2,
                    "anchored_snapshots": 1,
                    "legacy_unanchored_snapshots": 0,
                },
                "map_position": {"snapshots": 1, "mutations": 1},
                "reward_ledger": {
                    "balances": 1,
                    "receipts": 1,
                    "quest_award_keys": 0,
                },
                "shop": {
                    "purchases": 1,
                    "linked_player_mutations": 1,
                    "linked_inventory_mutations": 1,
                },
            },
        )

    def test_corrupt_shop_receipt_amount_fails_closed(self):
        connection = sqlite3.connect(self.path)
        row = connection.execute(
            "SELECT result_json FROM shop_purchase_receipts "
            "WHERE request_id='shop-purchase-1'"
        ).fetchone()
        receipt = json.loads(row[0])
        receipt["total"] = 8
        connection.execute(
            "UPDATE shop_purchase_receipts SET result_json=? "
            "WHERE request_id='shop-purchase-1'",
            (json.dumps(receipt, sort_keys=True, separators=(",", ":")),),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError, "shop integrity audit failed"
        ):
            inspect_domain_database(self.path)

    def test_orphan_shop_receipt_mutations_fail_closed(self):
        connection = sqlite3.connect(self.path)
        connection.execute(
            "DELETE FROM shop_purchase_receipts WHERE request_id='shop-purchase-1'"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError, "shop integrity audit failed"
        ):
            inspect_domain_database(self.path)

    def test_missing_shop_receipt_table_rejects_reserved_mutations(self):
        missing = Path(self.temp.name) / "missing-shop-receipts.sqlite3"
        connection = sqlite3.connect(missing)
        source = sqlite3.connect(self.path)
        source.backup(connection)
        source.close()
        connection.execute("DROP TABLE shop_purchase_receipts")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError,
            "shop receipt schema is missing for reserved shop mutations",
        ):
            inspect_domain_database(missing)

    def test_partial_shop_schema_fails_closed(self):
        partial = Path(self.temp.name) / "partial-shop.sqlite3"
        connection = sqlite3.connect(partial)
        connection.execute(
            "CREATE TABLE shop_purchase_receipts (request_id TEXT PRIMARY KEY)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(DomainAuditError, "shop schema is incomplete"):
            inspect_domain_database(partial)

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

    def test_partial_reward_ledger_schema_fails_closed(self):
        partial = Path(self.temp.name) / "partial-reward-ledger.sqlite3"
        connection = sqlite3.connect(partial)
        connection.execute(
            "CREATE TABLE reward_balances ("
            "player_id TEXT NOT NULL, item_id TEXT NOT NULL, "
            "quantity INTEGER NOT NULL, PRIMARY KEY(player_id, item_id))"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError, "reward_ledger schema is incomplete"
        ):
            inspect_domain_database(partial)

    def test_corrupt_reward_balance_fails_closed(self):
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE reward_balances SET quantity=3 "
            "WHERE player_id='hero' AND item_id='gem'"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError, "reward_ledger integrity audit failed"
        ):
            inspect_domain_database(self.path)

    def test_partial_quest_award_schema_requires_inventory_receipts(self):
        partial = Path(self.temp.name) / "partial-quest-awards.sqlite3"
        connection = sqlite3.connect(partial)
        connection.execute(
            "CREATE TABLE quest_inventory_awards (request_id TEXT PRIMARY KEY)"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError,
            "quest_inventory_awards requires complete inventory schema",
        ):
            inspect_domain_database(partial)

    def test_corrupt_quest_award_payload_fails_closed(self):
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE quest_inventory_awards SET payload_json=? "
            "WHERE request_id='quest-award-1'",
            ('["hero",7,"other",2,1]',),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError,
            "quest_inventory_awards integrity audit failed",
        ):
            inspect_domain_database(self.path)

    def test_orphan_quest_inventory_mutation_fails_closed(self):
        connection = sqlite3.connect(self.path)
        connection.execute(
            "DELETE FROM quest_inventory_awards WHERE request_id='quest-award-1'"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError,
            "quest_inventory_awards integrity audit failed",
        ):
            inspect_domain_database(self.path)

    def test_missing_quest_award_table_rejects_reserved_inventory_mutation(self):
        missing_awards = Path(self.temp.name) / "missing-quest-awards.sqlite3"
        connection = sqlite3.connect(missing_awards, isolation_level=None)
        inventory = SqliteInventoryStore(connection)
        inventory.create("hero")
        inventory.apply("hero", "quest-orphan", 0, [("gem", 1)])
        connection.close()
        with self.assertRaisesRegex(
            DomainAuditError,
            "quest inventory award schema is missing for reserved inventory mutations",
        ):
            inspect_domain_database(missing_awards)

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

    def test_read_only_audit_classifies_legacy_player_schema_without_migration(self):
        legacy = Path(self.temp.name) / "legacy-player.sqlite3"
        connection = sqlite3.connect(legacy)
        connection.execute(
            """CREATE TABLE player_state_snapshots (
                character_id TEXT PRIMARY KEY,
                level INTEGER NOT NULL,
                experience INTEGER NOT NULL,
                currency INTEGER NOT NULL,
                revision INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE player_state_mutations (
                request_id TEXT PRIMARY KEY,
                character_id TEXT NOT NULL,
                expected_revision INTEGER NOT NULL,
                requested_level INTEGER,
                experience_delta INTEGER NOT NULL,
                currency_delta INTEGER NOT NULL,
                result_level INTEGER NOT NULL,
                result_experience INTEGER NOT NULL,
                result_currency INTEGER NOT NULL,
                result_revision INTEGER NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO player_state_snapshots VALUES ('legacy', 3, 17, 45, 1)"
        )
        connection.execute(
            """INSERT INTO player_state_mutations VALUES
               ('legacy-1', 'legacy', 0, NULL, 5, 5, 3, 17, 45, 1)"""
        )
        connection.commit()
        connection.close()

        before = legacy.read_bytes()
        result = inspect_domain_database(legacy)
        self.assertEqual(
            result["audits"]["player_state"],
            {
                "snapshots": 1,
                "mutations": 1,
                "anchored_snapshots": 0,
                "legacy_unanchored_snapshots": 1,
            },
        )
        self.assertEqual(legacy.read_bytes(), before)

        read_only = sqlite3.connect(legacy.as_uri() + "?mode=ro", uri=True)
        try:
            columns = {
                row[1] for row in read_only.execute(
                    "PRAGMA table_info(player_state_snapshots)"
                )
            }
            tables = {
                row[0] for row in read_only.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            read_only.close()
        self.assertNotIn("baseline_version", columns)
        self.assertNotIn("player_state_creations", tables)

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
