"""Local-only map occupancy index backed by the synthetic session registry.

A process-local re-entrant lock serializes map membership. Membership is keyed
by stable Session object identity, not the replaceable connection identifier,
so a verified local handoff cannot orphan an in-map occupant. This remains
synthetic and does not imply any AOW map or room contract.
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
        self._member_keys = {}
        self._join_serial = 0
        self._join_epochs = {}
        self._lock = threading.RLock()

    def join(self, connection_id, map_id):
        """Atomically reserve one local map slot and advance the session."""
        with self._lock:
            # Keep the registry key stable until the session transition and
            # matching stable-identity membership entry have been published.
            with self.registry.locked_session(connection_id) as session:
                if session.snapshot.phase is not Phase.CHARACTER_SELECTED:
                    raise SessionError("map join not allowed")
                if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
                    raise SessionError("invalid map identifier")
                # Reconcile externally closed sessions before applying map capacity.
                # Both locks are re-entrant for this same thread.
                self.prune()
                members = self._members.get(map_id, set())
                if len(members) >= self.capacity_per_map:
                    raise ValueError("map capacity exceeded")
                session.join_map(map_id)
                self._members.setdefault(map_id, set()).add(session)
                self._member_keys[session] = connection_id
                self._join_serial += 1
                self._join_epochs[session] = self._join_serial

    def leave(self, connection_id):
        with self._lock:
            with self.registry.locked_session(connection_id) as session:
                if session.snapshot.phase is not Phase.IN_MAP:
                    raise SessionError("map leave not allowed")
                map_id = session.snapshot.map_id
                session.leave_map()
                self._discard(session, map_id)

    def _discard(self, session, map_id):
        self._join_epochs.pop(session, None)
        self._member_keys.pop(session, None)
        members = self._members.get(map_id)
        if members is not None:
            members.discard(session)
            if not members:
                del self._members[map_id]

    def disconnect(self, connection_id):
        with self._lock:
            with self.registry.locked_session(connection_id) as session:
                map_id = session.snapshot.map_id
                closed = self.registry.close(connection_id)
                if map_id is not None:
                    self._discard(session, map_id)
                return closed

    def join_epoch(self, connection_id):
        """Return the local occupancy incarnation only for a current member."""
        with self._lock:
            try:
                with self.registry.locked_session(connection_id) as session:
                    snapshot = session.snapshot
                    if snapshot.phase is not Phase.IN_MAP or snapshot.map_id is None:
                        return None
                    if session not in self._members.get(snapshot.map_id, set()):
                        return None
                    return self._join_epochs.get(session)
            except RegistryError:
                return None

    def prune(self):
        """Reconcile occupancy after sessions closed outside MapOccupancy.

        This is local defensive cleanup, not an APK network operation.
        Returns the number of stale membership entries removed.
        """
        with self._lock:
            removed = 0
            for map_id, members in tuple(self._members.items()):
                for session in tuple(members):
                    snap = session.snapshot
                    valid = (
                        self.registry.connection_id_for(session) is not None
                        and snap.phase is Phase.IN_MAP
                        and snap.map_id == map_id
                    )
                    if not valid:
                        self._discard(session, map_id)
                        removed += 1
            return removed

    def members(self, map_id):
        if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
            raise ValueError("invalid map identifier")
        with self._lock:
            members = self._members.get(map_id, set())
            current_states = self.registry.connection_states_for(members)
            resolved = set()
            for session, (current_key, snapshot) in current_states.items():
                if current_key is not None:
                    # A live session that left or changed maps outside this
                    # index is not an occupant, even before prune removes its
                    # stale index entry.
                    if snapshot.phase is Phase.IN_MAP and snapshot.map_id == map_id:
                        self._member_keys[session] = current_key
                        resolved.add(current_key)
                    continue
                # Preserve the last-known key only for closed stale entries;
                # this is diagnostic compatibility, not live occupancy.
                last_key = self._member_keys.get(session)
                if last_key is not None:
                    resolved.add(last_key)
            return frozenset(resolved)

    def close_all(self):
        with self._lock:
            self.registry.close_all()
            self._members.clear()
            self._member_keys.clear()
            self._join_epochs.clear()
