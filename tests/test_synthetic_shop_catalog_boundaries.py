"""Synthetic shop catalog and purchase boundary tests (not AOW wire fixtures)."""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_inventory import SessionInventory
from server.synthetic_session_wallet import SessionWallet
from server.synthetic_session_shop import Offer, SessionShop, ShopError


def ready_resources():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("hero")
    wallet = SessionWallet(maximum=100)
    inventory = SessionInventory(capacity=1, max_stack=3)
    wallet.initialize(session, 30)
    inventory.initialize(session)
    return session, wallet, inventory


class ShopBoundaryTests(unittest.TestCase):
    def test_rejects_duplicate_and_invalid_catalog_entries(self):
        bad_catalogs = (
            [Offer("potion", 1), Offer("potion", 2)],
            [Offer("potion", True)],
            [Offer("potion", 0)],
            [Offer("potion", 2_000_000_001)],
            [Offer("bad item", 1)],
            [Offer("", 1)],
            [Offer("a" * 129, 1)],
            [Offer("é", 1)],
            [object()],
        )
        for offers in bad_catalogs:
            with self.subTest(offers=repr(offers)):
                with self.assertRaises(ShopError):
                    SessionShop(offers)

    def test_invalid_quantities_never_charge(self):
        session, wallet, inventory = ready_resources()
        shop = SessionShop([Offer("potion", 2)])
        for quantity in (0, -1, True, 1.5, "2", None, 4):
            with self.subTest(quantity=quantity):
                with self.assertRaises(ShopError):
                    shop.buy(session, wallet, inventory, "potion", quantity)
                self.assertEqual(wallet.balance, 30)
                self.assertEqual(inventory.items, ())

    def test_capacity_rejection_preserves_balance_and_items(self):
        session, wallet, inventory = ready_resources()
        shop = SessionShop([Offer("potion", 2), Offer("sword", 4)])
        shop.buy(session, wallet, inventory, "potion", 1)
        previous_balance, previous_items = wallet.balance, inventory.items
        with self.assertRaises(ShopError):
            shop.buy(session, wallet, inventory, "sword", 1)
        self.assertEqual(wallet.balance, previous_balance)
        self.assertEqual(inventory.items, previous_items)

    def test_cost_exceeding_wallet_maximum_is_rejected_without_mutation(self):
        session, wallet, inventory = ready_resources()
        shop = SessionShop([Offer("expensive", 60)])
        with self.assertRaises(ShopError):
            shop.buy(session, wallet, inventory, "expensive", 2)
        self.assertEqual(wallet.balance, 30)
        self.assertEqual(inventory.items, ())


if __name__ == "__main__":
    unittest.main()
