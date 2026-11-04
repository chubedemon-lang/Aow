"""Tests for synthetic server domain only; no APK protocol assertions."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
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


    def test_inventory_grant_consume_and_persist(self):
        character = self.domain.create_character("alice", "hero")
        cid = character["id"]
        self.assertEqual(self.domain.list_inventory(cid), [])
        self.assertEqual(self.domain.change_inventory(cid, "test_item", 5), {"item_id": "test_item", "quantity": 5})
        reopened = Domain(self.domain.database)
        self.assertEqual(reopened.list_inventory(cid), [{"item_id": "test_item", "quantity": 5}])
        self.assertEqual(reopened.change_inventory(cid, "test_item", -3)["quantity"], 2)
        self.assertEqual(reopened.change_inventory(cid, "test_item", -2)["quantity"], 0)
        self.assertEqual(reopened.list_inventory(cid), [])

    def test_inventory_rejects_bad_inputs_without_mutating(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        for bad_delta in (0, True, 1.5, 1_000_001):
            with self.assertRaises(ValueError):
                self.domain.change_inventory(cid, "test_item", bad_delta)
        for bad_item in ("", "spaces are invalid", "a" * 65, "id/other"):
            with self.assertRaises(ValueError):
                self.domain.change_inventory(cid, bad_item, 1)
        with self.assertRaises(ValueError):
            self.domain.change_inventory(cid, "test_item", -1)
        with self.assertRaises(KeyError):
            self.domain.change_inventory(9999, "test_item", 1)
        with self.assertRaises(KeyError):
            self.domain.list_inventory(9999)
        self.assertEqual(self.domain.list_inventory(cid), [])

    def test_inventory_atomic_concurrent_updates(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.domain.change_inventory(cid, "test_item", 1), range(40)))
        self.assertEqual(self.domain.list_inventory(cid), [{"item_id": "test_item", "quantity": 40}])


    def test_shop_purchase_debits_wallet_and_grants_item(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 30)
        self.assertEqual(self.domain.credit_wallet(cid, 100), 100)
        receipt = self.domain.buy_item(cid, "potion", 2)
        self.assertEqual(receipt, {"item_id": "potion", "quantity_purchased": 2, "total": 60, "balance": 40})
        self.assertEqual(Domain(self.domain.database).list_inventory(cid), [{"item_id": "potion", "quantity": 2}])

    def test_shop_insufficient_funds_rolls_back(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 50)
        self.domain.credit_wallet(cid, 10)
        with self.assertRaises(ValueError):
            self.domain.buy_item(cid, "potion")
        self.assertEqual(self.domain.list_inventory(cid), [])
        self.assertEqual(self.domain.credit_wallet(cid, 1), 11)

    def test_shop_disabled_and_invalid_requests(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 1, False)
        self.domain.credit_wallet(cid, 10)
        with self.assertRaises(KeyError):
            self.domain.buy_item(cid, "potion")
        for invalid in (True, 0, 101, 1.5):
            with self.assertRaises(ValueError):
                self.domain.buy_item(cid, "potion", invalid)
        with self.assertRaises(KeyError):
            self.domain.buy_item(999, "potion")
        with self.assertRaises(ValueError):
            self.domain.credit_wallet(cid, True)

    def test_shop_concurrent_purchase_cannot_overspend(self):
        cid = self.domain.create_character("alice", "hero")["id"]
        self.domain.set_shop_item("potion", 10)
        self.domain.credit_wallet(cid, 100)
        def purchase(_):
            try:
                self.domain.buy_item(cid, "potion")
                return True
            except ValueError:
                return False
        with ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(purchase, range(20)))
        self.assertEqual(sum(results), 10)
        self.assertEqual(self.domain.list_inventory(cid), [{"item_id": "potion", "quantity": 10}])
        self.assertEqual(self.domain.credit_wallet(cid, 1), 1)


if __name__ == "__main__":
    unittest.main()
