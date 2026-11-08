"""Synthetic wallet tests; not an AOW currency contract."""
import unittest

from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_session_wallet import SessionWallet, WalletError


def ready():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("hero")
    return session


class WalletTests(unittest.TestCase):
    def test_credit_debit_and_boundaries(self):
        session, wallet = ready(), SessionWallet(maximum=10)
        self.assertEqual(wallet.initialize(session, 7), 7)
        self.assertEqual(wallet.credit(session, 3), 10)
        self.assertEqual(wallet.debit(session, 10), 0)

    def test_rejected_transactions_are_atomic(self):
        session, wallet = ready(), SessionWallet(maximum=10)
        wallet.initialize(session, 7)
        for operation, amount in ((wallet.credit, 4), (wallet.debit, 8),
                                  (wallet.credit, True), (wallet.debit, 0),
                                  (wallet.credit, -1), (wallet.debit, 1.5)):
            with self.assertRaises(WalletError):
                operation(session, amount)
            self.assertEqual(wallet.balance, 7)

    def test_invalid_initialization_and_duplicate(self):
        for maximum in (0, True, 2_000_000_001):
            with self.assertRaises(WalletError):
                SessionWallet(maximum)
        session, wallet = ready(), SessionWallet(10)
        for initial in (-1, 11, True, 1.5):
            with self.assertRaises(WalletError):
                wallet.initialize(session, initial)
            self.assertIsNone(wallet.balance)
        wallet.initialize(session, 0)
        with self.assertRaises(WalletError):
            wallet.initialize(session)

    def test_close_revokes_even_on_rejected_debit(self):
        session, wallet = ready(), SessionWallet()
        wallet.initialize(session, 5)
        session.close()
        with self.assertRaises(WalletError):
            wallet.debit(session, 1)
        self.assertIsNone(wallet.balance)

    def test_map_transition_revokes_epoch(self):
        session, wallet = ready(), SessionWallet()
        wallet.initialize(session, 5)
        session.join_map("map_a")
        with self.assertRaises(WalletError):
            wallet.credit(session, 1)
        self.assertIsNone(wallet.balance)

    def test_cross_session_fails_closed(self):
        first, second, wallet = ready(), ready(), SessionWallet()
        wallet.initialize(first, 9)
        with self.assertRaises(WalletError):
            wallet.debit(second, 1)
        self.assertIsNone(wallet.balance)
        self.assertEqual(wallet.initialize(second, 3), 3)


if __name__ == "__main__":
    unittest.main()
