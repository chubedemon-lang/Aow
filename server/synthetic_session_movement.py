"""Map-scoped movement adapter for synthetic session lifecycle tests.

Not a verified AOW movement packet, physics model, or coordinate system.
"""
from server.synthetic_session_lifecycle import SessionState
from server.synthetic_movement import MovementError, MovementState, Position


class SessionMovement:
    """Bind a synthetic actor's movement to the current session map.

    Explicitly sync after session transitions. A map exit/change invalidates
    the old actor state; callers must spawn a fresh actor on the new map.
    """

    def __init__(self):
        self._actor = None
        self._map = None
        self._snapshot = None

    @property
    def actor(self):
        return self._actor

    def sync(self, session):
        snapshot = session.snapshot
        if snapshot.state is not SessionState.IN_MAP or snapshot.map_id != self._map or snapshot is not self._snapshot:
            if self._actor is not None:
                self._actor.close()
            self._actor = None
            self._map = None
            self._snapshot = None
        return self._actor

    def spawn(self, session, start, max_step):
        snapshot = session.snapshot
        # Revoke any previous actor even when this spawn request is invalid.
        # Otherwise a closed or departed session can retain a live actor.
        self.sync(session)
        if snapshot.state is not SessionState.IN_MAP:
            raise MovementError("session is not in a map")
        if self._actor is not None:
            raise MovementError("actor already spawned")
        # MovementState uses integer map IDs; the session lifecycle uses
        # opaque strings. Keep the string binding separately, without
        # pretending either is an AOW protocol identifier.
        actor = MovementState(0, start, max_step)
        self._actor = actor
        self._map = snapshot.map_id
        self._snapshot = snapshot
        return actor

    def move(self, session, tick, target):
        snapshot = session.snapshot
        if snapshot.state is not SessionState.IN_MAP or snapshot.map_id != self._map or snapshot is not self._snapshot:
            self.sync(session)
            raise MovementError("session map is not active")
        if self._actor is None:
            raise MovementError("actor not spawned")
        return self._actor.move(0, tick, target)
