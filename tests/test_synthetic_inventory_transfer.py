import unittest
from server.synthetic_inventory import Inventory, InventoryError
from server.synthetic_inventory_transfer import transfer


class TransferTests(unittest.TestCase):
    def test_transfer_success(self):
        a, b = Inventory(), Inventory()
        a.add(10, 5)
        self.assertEqual(transfer(a, b, 10, 3), ({10: 2}, {10: 3}))

    def test_destination_full_no_partial_write(self):
        a, b = Inventory(), Inventory(capacity=1)
        a.add(10, 5)
        b.add(20, 1)
        with self.assertRaises(InventoryError):
            transfer(a, b, 10, 1)
        self.assertEqual((a.snapshot(), b.snapshot()), ({10: 5}, {20: 1}))

    def test_destination_stack_limit_no_partial_write(self):
        a, b = Inventory(), Inventory(max_stack=3)
        a.add(10, 5)
        b.add(10, 2)
        with self.assertRaises(InventoryError):
            transfer(a, b, 10, 2)
        self.assertEqual((a.count(10), b.count(10)), (5, 2))

    def test_source_insufficient_no_partial_write(self):
        a, b = Inventory(), Inventory()
        a.add(10, 1)
        with self.assertRaises(InventoryError):
            transfer(a, b, 10, 2)
        self.assertEqual((a.snapshot(), b.snapshot()), ({10: 1}, {}))

    def test_self_transfer_rejected(self):
        a = Inventory()
        a.add(10, 2)
        with self.assertRaises(InventoryError):
            transfer(a, a, 10, 1)
        self.assertEqual(a.count(10), 2)

    def test_invalid_quantity_rejected(self):
        a, b = Inventory(), Inventory()
        for q in (True, 0, -1, 1.5):
            with self.assertRaises(InventoryError):
                transfer(a, b, 10, q)
        self.assertEqual((a.snapshot(), b.snapshot()), ({}, {}))

    def test_distinct_inventory_constraints(self):
        a, b = Inventory(max_stack=100), Inventory(max_stack=2)
        a.add(10, 10)
        self.assertEqual(transfer(a, b, 10, 2), ({10: 8}, {10: 2}))


if __name__ == "__main__":
    unittest.main()
