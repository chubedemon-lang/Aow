"""Transport-independent, synthetic movement validation; not AOW wire protocol."""
from dataclasses import dataclass
import math


def _finite_float(value):
    """Return a finite float for an exact built-in int/float, or None."""
    # Do not invoke caller-defined __float__ methods on numeric subclasses.
    # bool is excluded implicitly because its exact type is not int.
    if type(value) not in (int, float):
        return None
    try:
        converted = float(value)
    except (OverflowError, ValueError):
        return None
    return converted if math.isfinite(converted) else None


@dataclass(frozen=True)
class Position:
    x: float
    y: float

    def __post_init__(self):
        if _finite_float(self.x) is None or _finite_float(self.y) is None:
            raise ValueError("position must have finite numeric coordinates")


class MovementError(ValueError):
    pass


class MovementValidator:
    def __init__(self, max_speed: float, epsilon: float = 1e-6):
        speed = _finite_float(max_speed)
        tolerance = _finite_float(epsilon)
        if speed is None or speed <= 0:
            raise ValueError("max_speed must be positive and finite")
        if tolerance is None or tolerance < 0:
            raise ValueError("epsilon must be non-negative and finite")
        self.max_speed = speed
        self.epsilon = tolerance

    def validate(self, old: Position, new: Position, elapsed_seconds: float) -> Position:
        # Exact instances avoid subclass attribute-access hooks during the
        # authoritative comparison. Persisted/API rows must be decoded first.
        if type(old) is not Position or type(new) is not Position:
            raise TypeError("exact Position instances required")
        elapsed = _finite_float(elapsed_seconds)
        if elapsed is None or elapsed <= 0:
            raise MovementError("invalid elapsed time")

        # Convert before subtraction: Python integers are unbounded, while the
        # movement calculation is intentionally performed in finite float space.
        dx = float(new.x) - float(old.x)
        dy = float(new.y) - float(old.y)
        if not math.isfinite(dx) or not math.isfinite(dy):
            raise MovementError("movement distance is outside the supported range")
        distance = math.hypot(dx, dy)
        allowed = self.max_speed * elapsed
        limit = allowed + self.epsilon
        # An overflowed allowance must never turn the check into "allow all".
        if not math.isfinite(distance) or not math.isfinite(allowed) or not math.isfinite(limit):
            raise MovementError("movement calculation is outside the supported range")
        if distance > limit:
            raise MovementError("movement exceeds synthetic speed limit")
        return new
