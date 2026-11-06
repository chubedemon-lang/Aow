"""Local-only map occupancy index backed by the synthetic session registry.

No APK packet format, map IDs or networking behavior is implied.
"""
from .synthetic_session_registry import SessionRegistry, RegistryError
from .synthetic_session_state import Phase, SessionError


class MapOccupancy:
    def __init__(self, registry: SessionRegistry, capacity_per_map=128):
        if not isinstance(registry, SessionRegistry):
            raise TypeError("registry must be SessionRegistry")
        if type(capacity_per_map) is not int or not 1 <= capacity_per_map <= 100000:
            raise ValueError("invalid map capacity")
        self.registry = registry
        self.capacity_per_map = capacity_per_map
        self._members = {}

    def join(self, connection_id, map_id):
        session = self.registry.get(connection_id)
        if session.snapshot.phase is not Phase.CHARACTER_SELECTED:
            raise SessionError("map join not allowed")
        if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
            raise SessionError("invalid map identifier")
        members = self._members.get(map_id, set())
        if len(members) >= self.capacity_per_map:
            raise ValueError("map capacity exceeded")
        session.join_map(map_id)
        self._members.setdefault(map_id, set()).add(connection_id)

    def leave(self, connection_id):
        session = self.registry.get(connection_id)
        if session.snapshot.phase is not Phase.IN_MAP:
            raise SessionError("map leave not allowed")
        map_id = session.snapshot.map_id
        session.leave_map()
        self._discard(connection_id, map_id)

    def _discard(self, connection_id, map_id):
        members = self._members.get(map_id)
        if members is not None:
            members.discard(connection_id)
            if not members:
                del self._members[map_id]

    def disconnect(self, connection_id):
        session = self.registry.get(connection_id)
        map_id = session.snapshot.map_id
        closed = self.registry.close(connection_id)
        if map_id is not None:
            self._discard(connection_id, map_id)
        return closed

    def members(self, map_id):
        if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
            raise ValueError("invalid map identifier")
        return frozenset(self._members.get(map_id, ()))

    def close_all(self):
        self.registry.close_all()
        self._members.clear()
