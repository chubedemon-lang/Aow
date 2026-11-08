"""Synthetic shop tests; these are not APK compatibility tests."""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_inventory import SessionInventory
from server.synthetic_session_wallet import SessionWallet
from server.synthetic_session_shop import Offer, SessionShop, ShopError


def setup(balance=10, capacity=2, max_stack=5):
    session = SyntheticSession()
    session.authenticate()
    session.select_character("hero")
    wallet = SessionWallet(maximum=100)
    inventory = SessionInventory(capacity=capacity, max_stack=max_stack)
    wallet.initialize(session, balance)
    inventory.initialize(session)
    return session, wallet, inventory


class ShopTests(unittest.TestCase):
    def setUp(self):
        self.shop = SessionShop([Offer("potion", 3), Offer("sword", 7)])

    def test_success_and_existing_stack(self):
        session, wallet, inv = setup()
        self.assertEqual(self.shop.buy(session, wallet, inv, "potion", 2)[0], 4)
        self.assertEqual(self.shop.buy(session, wallet, inv, "potion")[0], 1)
        self.assertEqual(inv.items[0].quantity, 3)

    def test_insufficient_funds_does_not_grant_items(self):
        session, wallet, inv = setup(balance=2)
        with self.assertRaises(ShopError):
            self.shop.buy(session, wallet, inv, "potion")
        self.assertEqual(wallet.balance, 2)
        self.assertEqual(inv.items, ())

    def test_capacity_and_stack_are_atomic(self):
        session, wallet, inv = setup(balance=100, capacity=1, max_stack=2)
        self.shop.buy(session, wallet, inv, "potion", 2)
        for item, count in (("potion", 1), ("sword", 1)):
            with self.assertRaises(ShopError):
                self.shop.buy(session, wallet, inv, item, count)
            self.assertEqual(wallet.balance, 94)
            self.assertEqual(inv.items[0].quantity, 2)

    def test_invalid_quantity_and_catalog(self):
        session, wallet, inv = setup()
        for quantity in (0, -1, True, 1.5, 100000):
            with self.assertRaises(ShopError):
                self.shop.buy(session, wallet, inv, "potion", quantity)
        with self.assertRaises(ShopError):
            self.shop.buy(session, wallet, inv, "unknown")
        self.assertEqual(wallet.balance, 10)
        for offers in ([Offer("x", 1), Offer("x", 2)],
                       [Offer("bad id", 1)], [Offer("x", True)],
                       [Offer("x", 0)]):
            with self.assertRaises(ShopError):
                SessionShop(offers)

    def test_close_revokes_both_resources(self):
        session, wallet, inv = setup()
        session.close()
        with self.assertRaises(ShopError):
            self.shop.buy(session, wallet, inv, "potion")
        self.assertIsNone(wallet.balance)
        self.assertIsNone(inv.items)

    def test_map_transition_revokes_both_resources(self):
        session, wallet, inv = setup()
        session.join_map("field")
        with self.assertRaises(ShopError):
            self.shop.buy(session, wallet, inv, "potion")
        self.assertIsNone(wallet.balance)
        self.assertIsNone(inv.items)


if __name__ == "__main__":
    unittest.main()
