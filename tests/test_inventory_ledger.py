"""Tests for the synthetic inventory ledger; no AOW client packet assumptions."""
import unittest

from server.inventory_ledger import InventoryError, InventoryLedger, ItemDefinition


class InventoryLedgerTests(unittest.TestCase):
    def setUp(self):
        self.ledger = InventoryLedger({
            "potion": ItemDefinition("potion", 10),
            "sword": ItemDefinition("sword", 1),
            "gem": ItemDefinition("gem", 100),
        }, slot_limit=2)

    def test_grant_and_consume(self):
        self.assertEqual(self.ledger.grant("alice", "potion", 5), {"potion": 5})
        self.assertEqual(self.ledger.consume("alice", "potion", 2), {"potion": 3})

    def test_consume_last_item_frees_slot(self):
        self.ledger.grant("alice", "potion", 1)
        self.assertEqual(self.ledger.consume("alice", "potion", 1), {})
        self.ledger.grant("alice", "sword", 1)
        self.ledger.grant("alice", "gem", 1)
        self.assertEqual(len(self.ledger.snapshot("alice")), 2)

    def test_stack_limit_is_atomic(self):
        self.ledger.grant("alice", "potion", 9)
        with self.assertRaises(InventoryError):
            self.ledger.grant("alice", "potion", 2)
        self.assertEqual(self.ledger.snapshot("alice"), {"potion": 9})

    def test_slot_limit_is_atomic(self):
        self.ledger.grant("alice", "potion", 1)
        self.ledger.grant("alice", "sword", 1)
        with self.assertRaises(InventoryError):
            self.ledger.grant("alice", "gem", 1)
        self.assertEqual(self.ledger.snapshot("alice"), {"potion": 1, "sword": 1})

    def test_insufficient_items_do_not_mutate(self):
        self.ledger.grant("alice", "potion", 1)
        with self.assertRaises(InventoryError):
            self.ledger.consume("alice", "potion", 2)
        self.assertEqual(self.ledger.snapshot("alice"), {"potion": 1})

    def test_players_are_isolated(self):
        self.ledger.grant("alice", "potion", 2)
        self.assertEqual(self.ledger.snapshot("bob"), {})
        self.ledger.grant("bob", "potion", 1)
        self.assertEqual(self.ledger.snapshot("alice"), {"potion": 2})

    def test_snapshots_cannot_mutate_internal_state(self):
        self.ledger.grant("alice", "potion", 1)
        self.ledger.snapshot("alice")["potion"] = 999
        self.assertEqual(self.ledger.snapshot("alice")["potion"], 1)

    def test_invalid_quantities_rejected(self):
        for quantity in (0, -1, True, 1.5, "2"):
            with self.assertRaises(InventoryError):
                self.ledger.grant("alice", "potion", quantity)
            with self.assertRaises(InventoryError):
                self.ledger.consume("alice", "potion", quantity)

    def test_unknown_item_and_invalid_player(self):
        for player, item in (("alice", "missing"), ("", "potion")):
            with self.assertRaises(InventoryError):
                self.ledger.grant(player, item, 1)

    def test_invalid_catalog_and_limits(self):
        with self.assertRaises(InventoryError):
            InventoryLedger({"wrong": ItemDefinition("potion", 1)}, 2)
        with self.assertRaises(InventoryError):
            InventoryLedger({}, 0)
        with self.assertRaises(InventoryError):
            ItemDefinition("x", True)


if __name__ == "__main__":
    unittest.main()
