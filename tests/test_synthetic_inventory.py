import unittest

from server.synthetic_inventory import Inventory, InventoryError


class InventoryTests(unittest.TestCase):
    def test_add_remove_snapshot(self):
        inv = Inventory(capacity=2, max_stack=10)
        inv.add(101, 5)
        old = inv.snapshot()
        inv.remove(101, 2)
        self.assertEqual(old, {101: 5})
        self.assertEqual(inv.snapshot(), {101: 3})
        inv.remove(101, 3)
        self.assertEqual(inv.snapshot(), {})

    def test_insufficient_items_preserves_state(self):
        inv = Inventory()
        inv.add(1, 2)
        with self.assertRaises(InventoryError):
            inv.remove(1, 3)
        self.assertEqual(inv.count(1), 2)

    def test_stack_overflow_preserves_state(self):
        inv = Inventory(max_stack=3)
        inv.add(1, 3)
        with self.assertRaises(InventoryError):
            inv.add(1, 1)
        self.assertEqual(inv.snapshot(), {1: 3})

    def test_capacity_failure_is_atomic(self):
        inv = Inventory(capacity=1)
        inv.add(1, 1)
        with self.assertRaises(InventoryError):
            inv.apply([(1, -1), (2, 1), (3, 1)])
        self.assertEqual(inv.snapshot(), {1: 1})

    def test_exchange_atomic(self):
        inv = Inventory(capacity=1)
        inv.add(1, 2)
        self.assertEqual(inv.apply([(1, -2), (2, 1)]), {2: 1})

    def test_duplicate_deltas_aggregate(self):
        inv = Inventory(max_stack=5)
        inv.apply([(1, 3), (1, 2)])
        self.assertEqual(inv.count(1), 5)
        with self.assertRaises(InventoryError):
            inv.apply([(1, -2), (1, 3)])
        self.assertEqual(inv.count(1), 5)

    def test_reject_invalid_input(self):
        inv = Inventory()
        for changes in (None, {}, [(True, 1)], [(1, True)], [(1, 0)],
                        [(0, 1)], [(1, 1, 2)], ["bad"], [(1, 1), (2, 0)]):
            with self.assertRaises(InventoryError):
                inv.apply(changes)
        self.assertEqual(inv.snapshot(), {})

    def test_invalid_configuration(self):
        for kwargs in ({"capacity": 0}, {"capacity": True},
                       {"max_stack": 0}, {"max_stack": False}):
            with self.assertRaises(InventoryError):
                Inventory(**kwargs)

    def test_reject_unbounded_batch_without_mutation(self):
        inv = Inventory()
        inv.add(1, 2)
        with self.assertRaises(InventoryError):
            inv.apply([(1, 1)] * 4097)
        self.assertEqual(inv.snapshot(), {1: 2})

    def test_reject_extreme_identifiers_and_deltas(self):
        inv = Inventory()
        for changes in ([(2**31, 1)], [(1, 2**31)], [(1, -(2**31))]):
            with self.assertRaises(InventoryError):
                inv.apply(changes)
        self.assertEqual(inv.snapshot(), {})

    def test_reject_excessive_configuration(self):
        for kwargs in ({"capacity": 4097}, {"max_stack": 2**31}):
            with self.assertRaises(InventoryError):
                Inventory(**kwargs)

    def test_instances_isolated(self):
        first, second = Inventory(), Inventory()
        first.add(1, 1)
        self.assertEqual(second.snapshot(), {})


if __name__ == "__main__":
    unittest.main()
