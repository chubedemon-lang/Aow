"""Local-only movement registry bound to synthetic map membership.

Does not implement or infer AOW packets, coordinates, physics, or map geometry.
"""
from .synthetic_map_occupancy import MapOccupancy
from .synthetic_movement import MovementState, MovementError, Position
from .synthetic_session_state import Phase


class MapMovementRegistry:
    def __init__(self, maps: MapOccupancy):
        if not isinstance(maps, MapOccupancy):
            raise TypeError("maps must be MapOccupancy")
        self.maps = maps
        self._actors = {}
        self._actor_epochs = {}

    def _map_id(self, connection_id):
        session = self.maps.registry.get(connection_id)
        snap = session.snapshot
        if snap.phase is not Phase.IN_MAP or connection_id not in self.maps.members(snap.map_id):
            raise MovementError("connection is not in map")
        return snap.map_id

    def spawn(self, connection_id, start: Position, max_step):
        map_id = self._map_id(connection_id)
        epoch = self.maps.join_epoch(connection_id)
        if connection_id in self._actors:
            old = self._actors[connection_id]
            if (self._actor_epochs.get(connection_id) == epoch
                    and old.map_id == map_id and not old.closed):
                raise MovementError("actor already spawned")
        actor = MovementState(map_id, start, max_step)
        self._actors[connection_id] = actor
        self._actor_epochs[connection_id] = epoch
        return actor.position

    def move(self, connection_id, tick, target: Position):
        map_id = self._map_id(connection_id)
        actor = self._actors.get(connection_id)
        if (actor is None or actor.map_id != map_id
                or self._actor_epochs.get(connection_id) != self.maps.join_epoch(connection_id)):
            raise MovementError("actor not spawned in current map")
        return actor.move(map_id, tick, target)

    def position(self, connection_id):
        map_id = self._map_id(connection_id)
        actor = self._actors.get(connection_id)
        return (actor.position if actor is not None and actor.map_id == map_id
                and not actor.closed and self._actor_epochs.get(connection_id) == self.maps.join_epoch(connection_id)
                else None)

    def clear(self, connection_id):
        actor = self._actors.pop(connection_id, None)
        self._actor_epochs.pop(connection_id, None)
        if actor is not None:
            actor.close()

    def prune(self):
        """Discard actors after leave/disconnect, including direct registry closes."""
        for key, actor in tuple(self._actors.items()):
            try:
                if (self._map_id(key) != actor.map_id
                        or self._actor_epochs.get(key) != self.maps.join_epoch(key)):
                    self.clear(key)
            except (ValueError, TypeError):
                self.clear(key)
