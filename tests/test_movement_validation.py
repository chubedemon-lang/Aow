"""Synthetic movement tests; no client packet compatibility claims."""
import math
import unittest
from server.movement_validation import Position, MovementValidator, MovementError


class MovementValidationTests(unittest.TestCase):
    def setUp(self):
        self.validator = MovementValidator(max_speed=5)

    def test_allowed_movement(self):
        self.assertEqual(self.validator.validate(Position(0, 0), Position(3, 4), 1), Position(3, 4))

    def test_excessive_movement(self):
        with self.assertRaises(MovementError):
            self.validator.validate(Position(0, 0), Position(10, 0), 1)

    def test_elapsed_time_zero(self):
        with self.assertRaises(MovementError):
            self.validator.validate(Position(0, 0), Position(0, 0), 0)

    def test_elapsed_time_nan(self):
        with self.assertRaises(MovementError):
            self.validator.validate(Position(0, 0), Position(0, 0), math.nan)

    def test_non_finite_coordinates(self):
        with self.assertRaises(ValueError):
            Position(math.inf, 0)

    def test_bool_coordinates_rejected(self):
        with self.assertRaises(ValueError):
            Position(True, 0)

    def test_wrong_position_type(self):
        with self.assertRaises(TypeError):
            self.validator.validate((0, 0), Position(0, 0), 1)

    def test_negative_time(self):
        with self.assertRaises(MovementError):
            self.validator.validate(Position(0, 0), Position(0, 0), -1)

    def test_constructor_rejects_invalid_speed_and_epsilon(self):
        for speed in (True, False, 0, -1, math.nan, math.inf, 10**1000):
            with self.subTest(speed=type(speed).__name__):
                with self.assertRaises(ValueError):
                    MovementValidator(speed)
        for epsilon in (True, -1, math.nan, math.inf, 10**1000):
            with self.subTest(epsilon=type(epsilon).__name__):
                with self.assertRaises(ValueError):
                    MovementValidator(5, epsilon)

    def test_position_rejects_integer_outside_finite_float_range(self):
        with self.assertRaises(ValueError):
            Position(10**1000, 0)

    def test_elapsed_time_rejects_boolean_and_unrepresentable_integer(self):
        for elapsed in (True, False, 10**1000):
            with self.subTest(elapsed=type(elapsed).__name__):
                with self.assertRaises(MovementError):
                    self.validator.validate(Position(0, 0), Position(0, 0), elapsed)

    def test_overflowed_distance_is_rejected(self):
        with self.assertRaises(MovementError):
            self.validator.validate(
                Position(-1.7e308, 0), Position(1.7e308, 0), 1
            )

    def test_overflowed_allowed_distance_is_not_treated_as_unlimited(self):
        with self.assertRaises(MovementError):
            self.validator.validate(
                Position(0, 0), Position(0, 0), 1e308
            )

    def test_zero_epsilon_uses_exact_speed_boundary(self):
        validator = MovementValidator(max_speed=5, epsilon=0)
        self.assertEqual(
            validator.validate(Position(0, 0), Position(3, 4), 1),
            Position(3, 4),
        )


if __name__ == "__main__":
    unittest.main()
