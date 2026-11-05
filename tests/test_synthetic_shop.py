"""Synthetic shop regression tests; no client wire fixtures."""
import unittest

from server.inventory_ledger import InventoryLedger, ItemDefinition
from server.synthetic_shop import ShopError, ShopOffer, SyntheticShop


class SyntheticShopTests(unittest.TestCase):
    def setUp(self):
        self.inventory = InventoryLedger({
            "potion": ItemDefinition("potion", 5),
            "sword": ItemDefinition("sword", 1),
        }, slot_limit=1)
        self.shop = SyntheticShop(self.inventory, {
            "heal": ShopOffer("heal", "potion", 7),
            "weapon": ShopOffer("weapon", "sword", 50),
        }, max_purchase_quantity=10)

    def test_purchase_debits_and_grants(self):
        self.shop.credit("alice", 100)
        result = self.shop.purchase("alice", "heal", 3)
        self.assertEqual(result["balance"], 79)
        self.assertEqual(result["total"], 21)
        self.assertEqual(self.inventory.snapshot("alice"), {"potion": 3})

    def test_exact_balance(self):
        self.shop.credit("alice", 7)
        self.shop.purchase("alice", "heal")
        self.assertEqual(self.shop.balance("alice"), 0)

    def test_insufficient_balance_does_not_grant(self):
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "heal")
        self.assertEqual(self.inventory.snapshot("alice"), {})

    def test_stack_overflow_does_not_debit(self):
        self.shop.credit("alice", 100)
        self.shop.purchase("alice", "heal", 4)
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "heal", 2)
        self.assertEqual(self.shop.balance("alice"), 72)
        self.assertEqual(self.inventory.snapshot("alice"), {"potion": 4})

    def test_slot_overflow_does_not_debit(self):
        self.shop.credit("alice", 100)
        self.shop.purchase("alice", "heal")
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "weapon")
        self.assertEqual(self.shop.balance("alice"), 93)

    def test_unknown_offer_is_rejected(self):
        self.shop.credit("alice", 100)
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "missing")
        self.assertEqual(self.shop.balance("alice"), 100)

    def test_invalid_quantities(self):
        self.shop.credit("alice", 100)
        for quantity in (0, -1, True, 11, 1.2, "2"):
            with self.subTest(quantity=quantity):
                with self.assertRaises(ShopError):
                    self.shop.purchase("alice", "heal", quantity)
        self.assertEqual(self.shop.balance("alice"), 100)

    def test_players_are_isolated(self):
        self.shop.credit("alice", 50)
        self.shop.credit("bob", 7)
        self.shop.purchase("bob", "heal")
        self.assertEqual(self.shop.balance("alice"), 50)
        self.assertEqual(self.inventory.snapshot("alice"), {})

    def test_credit_validation(self):
        for amount in (0, -1, True, 1.5):
            with self.assertRaises(ShopError):
                self.shop.credit("alice", amount)
        with self.assertRaises(ShopError):
            self.shop.credit("", 1)

    def test_offer_and_shop_configuration_validation(self):
        with self.assertRaises(ShopError):
            ShopOffer("x", "potion", True)
        with self.assertRaises(ShopError):
            SyntheticShop(self.inventory, {"wrong": ShopOffer("x", "potion", 1)})
        with self.assertRaises(ShopError):
            SyntheticShop(self.inventory, {}, 0)

    def test_unknown_inventory_item_does_not_debit(self):
        shop = SyntheticShop(self.inventory, {"bad": ShopOffer("bad", "absent", 3)})
        shop.credit("alice", 10)
        with self.assertRaises(ShopError):
            shop.purchase("alice", "bad")
        self.assertEqual(shop.balance("alice"), 10)


if __name__ == "__main__":
    unittest.main()
