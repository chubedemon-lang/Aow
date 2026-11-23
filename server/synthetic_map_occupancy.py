"""Local-only map occupancy index backed by the synthetic session registry.

A process-local re-entrant lock makes map-capacity admission and the matching
session/membership updates atomic among callers using this MapOccupancy
instance. It does not provide cross-process or multi-instance capacity
coordination, and it does not imply any AOW map or room contract.
"""
import threading

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
        self._join_serial = 0
        self._join_epochs = {}
        self._lock = threading.RLock()

    def join(self, connection_id, map_id):
        """Atomically reserve one local map slot and advance the session."""
        with self._lock:
            session = self.registry.get(connection_id)
            if session.snapshot.phase is not Phase.CHARACTER_SELECTED:
                raise SessionError("map join not allowed")
            if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
                raise SessionError("invalid map identifier")
            # Reconcile externally closed sessions before applying map capacity.
            # The RLock keeps this prune/check/transition/insert sequence atomic
            # against other operations on this occupancy instance.
            self.prune()
            members = self._members.get(map_id, set())
            if len(members) >= self.capacity_per_map:
                raise ValueError("map capacity exceeded")
            session.join_map(map_id)
            self._members.setdefault(map_id, set()).add(connection_id)
            self._join_serial += 1
            self._join_epochs[connection_id] = self._join_serial

    def leave(self, connection_id):
        with self._lock:
            session = self.registry.get(connection_id)
            if session.snapshot.phase is not Phase.IN_MAP:
                raise SessionError("map leave not allowed")
            map_id = session.snapshot.map_id
            session.leave_map()
            self._discard(connection_id, map_id)

    def _discard(self, connection_id, map_id):
        self._join_epochs.pop(connection_id, None)
        members = self._members.get(map_id)
        if members is not None:
            members.discard(connection_id)
            if not members:
                del self._members[map_id]

    def disconnect(self, connection_id):
        with self._lock:
            session = self.registry.get(connection_id)
            map_id = session.snapshot.map_id
            closed = self.registry.close(connection_id)
            if map_id is not None:
                self._discard(connection_id, map_id)
            return closed

    def join_epoch(self, connection_id):
        """Local occupancy incarnation; never an APK protocol field."""
        with self._lock:
            return self._join_epochs.get(connection_id)

    def prune(self):
        """Reconcile occupancy after sessions closed outside MapOccupancy.

        This is local defensive cleanup, not an APK network operation.
        Returns the number of stale membership entries removed.
        """
        with self._lock:
            removed = 0
            for map_id, members in tuple(self._members.items()):
                for connection_id in tuple(members):
                    try:
                        snap = self.registry.get(connection_id).snapshot
                        valid = snap.phase is Phase.IN_MAP and snap.map_id == map_id
                    except RegistryError:
                        valid = False
                    if not valid:
                        self._discard(connection_id, map_id)
                        removed += 1
            return removed

    def members(self, map_id):
        if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
            raise ValueError("invalid map identifier")
        with self._lock:
            return frozenset(self._members.get(map_id, ()))

    def close_all(self):
        with self._lock:
            self.registry.close_all()
            self._members.clear()
            self._join_epochs.clear()
