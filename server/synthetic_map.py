"""Transport-independent synthetic map occupancy, not an AOW protocol.

This local domain model has no inferred APK map IDs, capacity or packets.
"""
from __future__ import annotations


class MapError(ValueError):
    """Rejected map occupancy transition."""


class MapRegistry:
    def __init__(self, capacities: dict[int, int]) -> None:
        if not isinstance(capacities, dict) or not capacities:
            raise MapError("capacities required")
        for map_id, capacity in capacities.items():
            if type(map_id) is not int or map_id < 0:
                raise MapError("invalid map id")
            if type(capacity) is not int or capacity <= 0:
                raise MapError("invalid capacity")
        self._capacities = dict(capacities)
        self._occupants = {map_id: set() for map_id in capacities}
        self._locations: dict[str, int] = {}

    @staticmethod
    def _validate_actor(actor_id: str) -> None:
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise MapError("invalid actor")

    def join(self, actor_id: str, map_id: int) -> None:
        self._validate_actor(actor_id)
        if type(map_id) is not int or map_id not in self._capacities:
            raise MapError("unknown map")
        if actor_id in self._locations:
            raise MapError("actor already joined")
        if len(self._occupants[map_id]) >= self._capacities[map_id]:
            raise MapError("map full")
        self._occupants[map_id].add(actor_id)
        self._locations[actor_id] = map_id

    def transfer(self, actor_id: str, destination: int) -> None:
        self._validate_actor(actor_id)
        if actor_id not in self._locations:
            raise MapError("actor not joined")
        if type(destination) is not int or destination not in self._capacities:
            raise MapError("unknown map")
        source = self._locations[actor_id]
        if source == destination:
            return
        if len(self._occupants[destination]) >= self._capacities[destination]:
            raise MapError("map full")
        self._occupants[source].remove(actor_id)
        self._occupants[destination].add(actor_id)
        self._locations[actor_id] = destination

    def leave(self, actor_id: str) -> None:
        self._validate_actor(actor_id)
        if actor_id not in self._locations:
            raise MapError("actor not joined")
        map_id = self._locations.pop(actor_id)
        self._occupants[map_id].remove(actor_id)

    def location(self, actor_id: str) -> int | None:
        self._validate_actor(actor_id)
        return self._locations.get(actor_id)

    def occupants(self, map_id: int) -> frozenset[str]:
        if type(map_id) is not int or map_id not in self._capacities:
            raise MapError("unknown map")
        return frozenset(self._occupants[map_id])
