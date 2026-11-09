import unittest

from server.synthetic_map_position import MapPosition, MapPositionError, Position


class MapPositionTests(unittest.TestCase):
    def test_immutable_lifecycle(self):
        initial = MapPosition()
        entered = initial.enter(0, Position(0, 0))
        moved = entered.move(Position(-5, 12), 1)
        left = moved.leave()
        self.assertEqual((initial.map_id, initial.revision), (None, 0))
        self.assertEqual((entered.position, entered.revision), (Position(0, 0), 1))
        self.assertEqual((moved.position, moved.revision), (Position(-5, 12), 2))
        self.assertEqual((left.map_id, left.position, left.revision), (None, None, 3))

    def test_invalid_coordinates(self):
        for x in (True, 2**31, -(2**31)-1, 1.5, "0"):
            with self.assertRaises(MapPositionError):
                Position(x, 0)

    def test_invalid_maps_and_snapshots(self):
        for map_id in (-1, True, 2**31, "1"):
            with self.assertRaises(MapPositionError):
                MapPosition().enter(map_id, Position(0, 0))
        for kwargs in ({"map_id": 1}, {"position": Position(0, 0)},
                       {"revision": True}, {"revision": -1}):
            with self.assertRaises(MapPositionError):
                MapPosition(**kwargs)

    def test_stale_moves_and_order(self):
        initial = MapPosition()
        with self.assertRaises(MapPositionError):
            initial.move(Position(1, 2), 0)
        with self.assertRaises(MapPositionError):
            initial.leave()
        entered = initial.enter(1, Position(0, 0))
        with self.assertRaises(MapPositionError):
            entered.enter(2, Position(1, 1))
        for revision in (0, True, 2, "1"):
            with self.assertRaises(MapPositionError):
                entered.move(Position(1, 2), revision)
        with self.assertRaises(MapPositionError):
            entered.move((1, 2), 1)
        self.assertEqual(entered.position, Position(0, 0))


if __name__ == "__main__":
    unittest.main()
