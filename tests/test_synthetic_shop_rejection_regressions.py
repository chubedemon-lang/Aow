"""Regression tests for synthetic shop input validation and rollback.

No assertions about the proprietary AOW wire protocol.
"""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_inventory import InventoryError, SessionInventory
from server.synthetic_session_wallet import SessionWallet
from server.synthetic_session_shop import Offer, SessionShop, ShopError


def resources():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("hero")
    wallet = SessionWallet(maximum=100)
    inventory = SessionInventory(capacity=2, max_stack=5)
    wallet.initialize(session, 20)
    inventory.initialize(session)
    return session, wallet, inventory


class RejectingInventory(SessionInventory):
    def add(self, session, item_id, quantity):
        raise InventoryError("injected failure")


class ShopRejectionTests(unittest.TestCase):
    def setUp(self):
        self.shop = SessionShop([Offer("potion", 3)])

    def test_unhashable_and_non_string_item_ids_do_not_charge(self):
        session, wallet, inventory = resources()
        for item_id in ([], {}, ["potion"], 1, None, True):
            with self.subTest(item_id=repr(item_id)):
                with self.assertRaises(ShopError):
                    self.shop.buy(session, wallet, inventory, item_id)
                self.assertEqual(wallet.balance, 20)
                self.assertEqual(inventory.items, ())

    def test_inventory_rejection_refunds_wallet(self):
        session, wallet, _ = resources()
        inventory = RejectingInventory(capacity=2, max_stack=5)
        inventory.initialize(session)
        with self.assertRaisesRegex(ShopError, "inventory rejected purchase"):
            self.shop.buy(session, wallet, inventory, "potion", 2)
        self.assertEqual(wallet.balance, 20)
        self.assertEqual(inventory.items, ())

    def test_rejected_purchase_preserves_existing_stack(self):
        session, wallet, inventory = resources()
        self.shop.buy(session, wallet, inventory, "potion", 2)
        before = inventory.items
        balance = wallet.balance
        with self.assertRaises(ShopError):
            self.shop.buy(session, wallet, inventory, "potion", 4)
        self.assertEqual(inventory.items, before)
        self.assertEqual(wallet.balance, balance)


if __name__ == "__main__":
    unittest.main()
