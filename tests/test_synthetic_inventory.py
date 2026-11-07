import unittest
from server.synthetic_inventory import Inventory

class InventoryTests(unittest.TestCase):
    def test_roundtrip(self):
        i = Inventory()
        self.assertEqual(i.apply({"potion": 2}, 0), 1)
        self.assertEqual(i.apply({"potion": -2}, 1), 2)
        self.assertEqual(i.stacks, {})

    def test_atomic_failure(self):
        i = Inventory()
        with self.assertRaises(ValueError):
            i.apply({"potion": 1, "coin": -1}, 0)
        self.assertEqual(i.stacks, {})
        self.assertEqual(i.revision, 0)

    def test_capacity(self):
        i = Inventory(1)
        with self.assertRaises(ValueError):
            i.apply({"a": 1, "b": 1}, 0)

    def test_stale_revision(self):
        i = Inventory()
        i.apply({"a": 1}, 0)
        with self.assertRaises(ValueError):
            i.apply({"a": 1}, 0)

    def test_bool_rejected(self):
        with self.assertRaises(ValueError):
            Inventory().apply({"a": True}, 0)

    def test_overflow(self):
        i = Inventory()
        i.apply({"a": 2147483647}, 0)
        with self.assertRaises(ValueError):
            i.apply({"a": 1}, 1)

if __name__ == "__main__":
    unittest.main()
