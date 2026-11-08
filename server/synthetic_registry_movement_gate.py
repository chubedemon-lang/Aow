"""Bounded synthetic movement gate for registry-owned sessions.

Not AOW wire framing, packet definitions, or coordinate semantics.
"""
from .synthetic_session_state import Phase


class RegistryMovementError(ValueError):
    pass


class RegistryMovementGate:
    def __init__(self, coordinate_limit=1000000):
        if type(coordinate_limit) is not int or not 1 <= coordinate_limit <= 100000000:
            raise RegistryMovementError("invalid coordinate limit")
        self.limit = coordinate_limit
        self._positions = {}

    def move(self, registry, connection_id, map_id, x, y):
        session = registry.get(connection_id)
        snapshot = session.snapshot
        if type(map_id) is not int or snapshot.phase is not Phase.IN_MAP or snapshot.map_id != map_id:
            raise RegistryMovementError("session not in requested map")
        if any(type(value) is not int or abs(value) > self.limit for value in (x, y)):
            raise RegistryMovementError("invalid coordinates")
        self._positions[id(session)] = (snapshot, x, y)
        return (x, y)

    def position(self, registry, connection_id):
        session = registry.get(connection_id)
        snapshot = session.snapshot
        record = self._positions.get(id(session))
        if snapshot.phase is not Phase.IN_MAP or record is None or record[0] is not snapshot:
            self._positions.pop(id(session), None)
            return None
        return record[1:]

    def forget(self, session):
        """Explicit cleanup for the session lifecycle owner on close."""
        self._positions.pop(id(session), None)
