import unittest

from server.synthetic_map import MapError, MapRegistry


class MapRegistryTests(unittest.TestCase):
    def setUp(self):
        self.maps = MapRegistry({1: 2, 2: 1})

    def test_join_and_snapshot(self):
        self.maps.join("a", 1)
        snapshot = self.maps.occupants(1)
        self.assertEqual(snapshot, frozenset({"a"}))
        self.maps.join("b", 1)
        self.assertEqual(snapshot, frozenset({"a"}))
        self.assertEqual(self.maps.location("b"), 1)

    def test_duplicate_join_rejected(self):
        self.maps.join("a", 1)
        with self.assertRaises(MapError):
            self.maps.join("a", 2)
        self.assertEqual(self.maps.location("a"), 1)

    def test_capacity_rejection_no_mutation(self):
        self.maps.join("a", 2)
        with self.assertRaises(MapError):
            self.maps.join("b", 2)
        self.assertIsNone(self.maps.location("b"))
        self.assertEqual(self.maps.occupants(2), frozenset({"a"}))

    def test_transfer_and_same_map_idempotent(self):
        self.maps.join("a", 1)
        self.maps.transfer("a", 1)
        self.maps.transfer("a", 2)
        self.assertEqual(self.maps.occupants(1), frozenset())
        self.assertEqual(self.maps.occupants(2), frozenset({"a"}))

    def test_failed_transfer_preserves_source(self):
        self.maps.join("a", 1)
        self.maps.join("b", 2)
        with self.assertRaises(MapError):
            self.maps.transfer("a", 2)
        self.assertEqual(self.maps.location("a"), 1)

    def test_leave_and_rejoin(self):
        self.maps.join("a", 1)
        self.maps.leave("a")
        self.assertIsNone(self.maps.location("a"))
        self.maps.join("a", 2)
        with self.assertRaises(MapError):
            self.maps.leave("missing")

    def test_invalid_ids_and_capacities(self):
        for capacities in ({}, {True: 1}, {1: True}, {1: 0}, {-1: 1}):
            with self.assertRaises(MapError):
                MapRegistry(capacities)
        for actor in ("", " ", None, 1):
            with self.assertRaises(MapError):
                self.maps.join(actor, 1)
        for map_id in (True, -1, "1", 3):
            with self.assertRaises(MapError):
                self.maps.join("a", map_id)


if __name__ == "__main__":
    unittest.main()
