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


if __name__ == "__main__":
    unittest.main()
