import unittest

from server.synthetic_movement import MovementError, MovementState, Position


class MovementTests(unittest.TestCase):
    def make_actor(self):
        return MovementState(2, Position(0, 0), 5)

    def test_valid_movement_and_zero_step(self):
        a = self.make_actor()
        self.assertEqual(a.move(2, 0, Position(3, 4)), Position(3, 4))
        self.assertEqual(a.move(2, 1, Position(3, 4)), Position(3, 4))

    def test_replay_and_out_of_order_rejected_without_mutation(self):
        a = self.make_actor()
        a.move(2, 10, Position(1, 1))
        for tick in (10, 9, -1, True, 1.5):
            with self.assertRaises(MovementError):
                a.move(2, tick, Position(2, 2))
        self.assertEqual((a.position, a.last_tick), (Position(1, 1), 10))

    def test_cross_map_rejected(self):
        a = self.make_actor()
        for map_id in (1, -1, True, "2"):
            with self.assertRaises(MovementError):
                a.move(map_id, 0, Position(1, 1))
        self.assertEqual(a.last_tick, -1)

    def test_oversized_step_rejected_and_next_valid_tick_allowed(self):
        a = self.make_actor()
        with self.assertRaises(MovementError):
            a.move(2, 0, Position(6, 0))
        self.assertEqual(a.move(2, 0, Position(5, 0)), Position(5, 0))

    def test_nonfinite_coordinates_and_invalid_constructor(self):
        for x in (float("nan"), float("inf"), "1", True):
            with self.assertRaises(MovementError):
                Position(x, 0)
        for speed in (0, -1, float("inf"), float("nan"), True):
            with self.assertRaises(MovementError):
                MovementState(2, Position(0, 0), speed)

    def test_close_revokes_movement(self):
        a = self.make_actor()
        a.close()
        with self.assertRaises(MovementError):
            a.move(2, 0, Position(1, 1))

    def test_actors_independent(self):
        a, b = self.make_actor(), self.make_actor()
        a.move(2, 0, Position(2, 2))
        self.assertEqual((b.position, b.last_tick), (Position(0, 0), -1))


if __name__ == "__main__":
    unittest.main()
