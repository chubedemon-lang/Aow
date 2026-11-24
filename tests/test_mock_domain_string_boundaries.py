"""Regression tests for synthetic mock-domain string input boundaries."""
import tempfile
import unittest
from pathlib import Path

from server.mock import Domain


class HostileText(str):
    """A string subclass that must be rejected before any custom hook runs."""

    def __len__(self):
        raise AssertionError("custom length hook must not run")

    def __iter__(self):
        raise AssertionError("custom iterator hook must not run")

    def __getitem__(self, key):
        raise AssertionError("custom index hook must not run")


class MockDomainStringBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.domain = Domain(Path(self.tempdir.name) / "mock.sqlite3")

    def test_character_fields_reject_subclasses_before_custom_hooks(self):
        for username, name in (
            (HostileText("account"), "Hero"),
            ("account", HostileText("Hero")),
        ):
            with self.subTest(username=type(username).__name__, name=type(name).__name__):
                with self.assertRaisesRegex(ValueError, "invalid"):
                    self.domain.create_character(username, name)
        with self.domain.connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM accounts").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM characters").fetchone()[0], 0)

    def test_inventory_and_shop_reject_item_subclasses_before_custom_hooks(self):
        character = self.domain.create_character("account", "Hero")
        character_id = character["id"]
        hostile = HostileText("potion")
        operations = (
            lambda: self.domain.change_inventory(character_id, hostile, 1),
            lambda: self.domain.set_shop_item(hostile, 10),
            lambda: self.domain.buy_item(character_id, hostile),
        )
        for operation in operations:
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(ValueError, "invalid item id"):
                    operation()
        with self.domain.connection() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM shop_catalog").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM inventory").fetchone()[0], 0)

    def test_builtin_strings_keep_existing_synthetic_behavior(self):
        character = self.domain.create_character("account", "Hero")
        character_id = character["id"]
        self.domain.change_inventory(character_id, "potion", 2)
        self.domain.set_shop_item("elixir", 10)
        self.domain.credit_wallet(character_id, 25)
        result = self.domain.buy_item(character_id, "elixir", 2)
        self.assertEqual(result["quantity_purchased"], 2)
        self.assertEqual(result["balance"], 5)
        self.assertEqual(
            self.domain.list_inventory(character_id),
            [
                {"item_id": "elixir", "quantity": 2},
                {"item_id": "potion", "quantity": 2},
            ],
        )


if __name__ == "__main__":
    unittest.main()
