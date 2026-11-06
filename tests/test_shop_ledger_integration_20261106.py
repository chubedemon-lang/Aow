"""Regression checks for the existing synthetic shop/ledger integration."""
import unittest

from server.inventory_ledger import InventoryLedger, ItemDefinition
from server.synthetic_shop import ShopError, ShopOffer, SyntheticShop


class ShopLedgerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.ledger = InventoryLedger({
            "apple": ItemDefinition("apple", 3),
            "pear": ItemDefinition("pear", 2),
        }, slot_limit=1)
        self.shop = SyntheticShop(self.ledger, {
            "apple-offer": ShopOffer("apple-offer", "apple", 7),
            "pear-offer": ShopOffer("pear-offer", "pear", 9),
        })
        self.shop.credit("alice", 50)
        self.shop.credit("bob", 50)

    def test_success_deducts_exact_total_and_grants_exact_quantity(self):
        result = self.shop.purchase("alice", "apple-offer", 2)
        self.assertEqual(result["total"], 14)
        self.assertEqual(self.shop.balance("alice"), 36)
        self.assertEqual(self.ledger.snapshot("alice"), {"apple": 2})

    def test_stack_limit_failure_does_not_charge(self):
        self.shop.purchase("alice", "apple-offer", 2)
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "apple-offer", 2)
        self.assertEqual(self.shop.balance("alice"), 36)
        self.assertEqual(self.ledger.snapshot("alice"), {"apple": 2})

    def test_slot_limit_failure_does_not_charge(self):
        self.shop.purchase("alice", "apple-offer")
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "pear-offer")
        self.assertEqual(self.shop.balance("alice"), 43)
        self.assertEqual(self.ledger.snapshot("alice"), {"apple": 1})

    def test_insufficient_funds_preserves_inventory(self):
        with self.assertRaises(ShopError):
            self.shop.purchase("alice", "pear-offer", 6)
        self.assertEqual(self.shop.balance("alice"), 50)
        self.assertEqual(self.ledger.snapshot("alice"), {})

    def test_players_isolated(self):
        self.shop.purchase("alice", "apple-offer")
        self.assertEqual(self.shop.balance("bob"), 50)
        self.assertEqual(self.ledger.snapshot("bob"), {})

    def test_invalid_quantities_do_not_change_state(self):
        for quantity in (True, 0, -1, 1.5, 100):
            with self.subTest(quantity=quantity), self.assertRaises(ShopError):
                self.shop.purchase("alice", "apple-offer", quantity)
        self.assertEqual(self.shop.balance("alice"), 50)
        self.assertEqual(self.ledger.snapshot("alice"), {})


if __name__ == "__main__":
    unittest.main()
