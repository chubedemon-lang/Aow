"""Synthetic inventory regression tests; no AOW APK assumptions."""
import unittest
from server.synthetic_session_inventory import InventoryError, SessionInventory, Stack
from server.synthetic_session_lifecycle import SyntheticSession

def ready():
    s = SyntheticSession()
    s.authenticate()
    s.select_character("hero")
    return s

class InventoryTests(unittest.TestCase):
    def test_add_remove_and_sorted_snapshots(self):
        s, inv = ready(), SessionInventory()
        self.assertEqual(inv.initialize(s), ())
        inv.add(s, "b", 3)
        snapshot = inv.add(s, "a", 2)
        self.assertEqual(snapshot, (Stack("a", 2), Stack("b", 3)))
        inv.remove(s, "b", 3)
        self.assertEqual(inv.items, (Stack("a", 2),))
        self.assertEqual(snapshot[1].quantity, 3)

    def test_capacity_and_overflow_are_atomic(self):
        s, inv = ready(), SessionInventory(capacity=1, max_stack=5)
        inv.initialize(s)
        inv.add(s, "a", 4)
        for item, count in (("a", 2), ("b", 1)):
            with self.assertRaises(InventoryError):
                inv.add(s, item, count)
            self.assertEqual(inv.items, (Stack("a", 4),))

    def test_invalid_types_and_underflow_are_atomic(self):
        s, inv = ready(), SessionInventory()
        inv.initialize(s)
        inv.add(s, "a", 3)
        for item, count in (("a", True), ("a", -1), ("a", 4),
                            ("bad/id", 1), ("a", 1.5)):
            with self.assertRaises(InventoryError):
                inv.remove(s, item, count)
            self.assertEqual(inv.items, (Stack("a", 3),))

    def test_session_close_revokes_on_rejected_operation(self):
        s, inv = ready(), SessionInventory()
        inv.initialize(s)
        inv.add(s, "a", 1)
        s.close()
        with self.assertRaises(InventoryError):
            inv.add(s, "a", 1)
        self.assertIsNone(inv.items)

    def test_map_epoch_revokes_inventory(self):
        s, inv = ready(), SessionInventory()
        inv.initialize(s)
        s.join_map("map_a")
        with self.assertRaises(InventoryError):
            inv.remove(s, "a", 1)
        self.assertIsNone(inv.items)

    def test_cross_session_isolation(self):
        a, b, inv = ready(), ready(), SessionInventory()
        inv.initialize(a)
        inv.add(a, "a", 1)
        with self.assertRaises(InventoryError):
            inv.add(b, "a", 1)
        self.assertIsNone(inv.items)
        self.assertEqual(inv.initialize(b), ())

    def test_constructor_limits_and_duplicate_init(self):
        for cap, stack in ((0, 10), (True, 10), (1, 0), (1, True)):
            with self.assertRaises(InventoryError):
                SessionInventory(cap, stack)
        s, inv = ready(), SessionInventory()
        inv.initialize(s)
        with self.assertRaises(InventoryError):
            inv.initialize(s)

if __name__ == "__main__":
    unittest.main()
