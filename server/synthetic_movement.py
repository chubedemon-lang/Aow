"""Synthetic server-side movement validation, NOT an AOW wire protocol.

Positions and tick values are local test-domain units. No game physics,
movement speeds, map dimensions, or client packet fields are inferred.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import isfinite, hypot


class MovementError(ValueError):
    """Invalid or unauthorized local movement."""


@dataclass(frozen=True)
class Position:
    x: float
    y: float

    def __post_init__(self) -> None:
        if any(type(v) not in (int, float) or not isfinite(v)
               for v in (self.x, self.y)):
            raise MovementError("position coordinates must be finite numbers")


class MovementState:
    """Single actor; authoritative map and monotonic tick validation."""

    def __init__(self, map_id: int, start: Position, max_step: float) -> None:
        if type(map_id) is not int or map_id < 0:
            raise MovementError("invalid map_id")
        if not isinstance(start, Position):
            raise MovementError("invalid start")
        if type(max_step) not in (int, float) or not isfinite(max_step) or max_step <= 0:
            raise MovementError("invalid max_step")
        self.map_id = map_id
        self.position = start
        self.max_step = max_step
        self.last_tick = -1
        self.closed = False

    def move(self, map_id: int, tick: int, target: Position) -> Position:
        if self.closed:
            raise MovementError("actor closed")
        if type(map_id) is not int or map_id != self.map_id:
            raise MovementError("map mismatch")
        if type(tick) is not int or tick < 0 or tick <= self.last_tick:
            raise MovementError("tick must increase")
        if not isinstance(target, Position):
            raise MovementError("invalid target")
        if hypot(target.x - self.position.x, target.y - self.position.y) > self.max_step:
            raise MovementError("step exceeds local limit")
        self.position = target
        self.last_tick = tick
        return self.position

    def close(self) -> None:
        self.closed = True
