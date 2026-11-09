"""Synthetic immutable map position state; not an AOW wire protocol."""
from dataclasses import dataclass, replace


class MapPositionError(ValueError):
    pass


@dataclass(frozen=True)
class Position:
    x: int
    y: int

    def __post_init__(self):
        for value in (self.x, self.y):
            if type(value) is not int or not -(2**31) <= value < 2**31:
                raise MapPositionError("invalid coordinate")


@dataclass(frozen=True)
class MapPosition:
    map_id: int | None = None
    position: Position | None = None
    revision: int = 0

    def __post_init__(self):
        if type(self.revision) is not int or self.revision < 0:
            raise MapPositionError("invalid revision")
        if (self.map_id is None) != (self.position is None):
            raise MapPositionError("inconsistent map state")
        if self.map_id is not None:
            if type(self.map_id) is not int or not 0 <= self.map_id < 2**31:
                raise MapPositionError("invalid map id")
            if type(self.position) is not Position:
                raise MapPositionError("invalid position")

    def enter(self, map_id: int, position: Position):
        if self.map_id is not None:
            raise MapPositionError("already in map")
        return replace(self, map_id=map_id, position=position, revision=self.revision + 1)

    def move(self, position: Position, expected_revision: int):
        if self.map_id is None:
            raise MapPositionError("not in map")
        if type(expected_revision) is not int or expected_revision != self.revision:
            raise MapPositionError("stale revision")
        if type(position) is not Position:
            raise MapPositionError("invalid position")
        return replace(self, position=position, revision=self.revision + 1)

    def leave(self):
        if self.map_id is None:
            raise MapPositionError("not in map")
        return replace(self, map_id=None, position=None, revision=self.revision + 1)
