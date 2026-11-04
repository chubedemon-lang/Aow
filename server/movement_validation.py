"""Transport-independent, synthetic movement validation; not AOW wire protocol."""
from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Position:
    x: float
    y: float

    def __post_init__(self):
        if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) for v in (self.x, self.y)):
            raise ValueError("position must have finite numeric coordinates")


class MovementError(ValueError):
    pass


class MovementValidator:
    def __init__(self, max_speed: float, epsilon: float = 1e-6):
        if not math.isfinite(max_speed) or max_speed <= 0:
            raise ValueError("max_speed must be positive and finite")
        self.max_speed = max_speed
        self.epsilon = epsilon

    def validate(self, old: Position, new: Position, elapsed_seconds: float) -> Position:
        if not isinstance(old, Position) or not isinstance(new, Position):
            raise TypeError("positions required")
        if not isinstance(elapsed_seconds, (int, float)) or isinstance(elapsed_seconds, bool) or not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
            raise MovementError("invalid elapsed time")
        if math.hypot(new.x - old.x, new.y - old.y) > self.max_speed * elapsed_seconds + self.epsilon:
            raise MovementError("movement exceeds synthetic speed limit")
        return new
