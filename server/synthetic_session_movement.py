"""Map-scoped movement adapter for synthetic session lifecycle tests.

Not a verified AOW movement packet, physics model, or coordinate system.
"""
from server.synthetic_session_lifecycle import SessionState
from server.synthetic_movement import MovementError, MovementState, Position


class SessionMovement:
    """Bind one synthetic actor to its exact session and lifecycle revision."""

    def __init__(self):
        self._actor = None
        self._map = None
        self._session = None
        self._revision = None

    @property
    def actor(self):
        return self._actor

    def _revoke(self):
        if self._actor is not None:
            self._actor.close()
        self._actor = None
        self._map = None
        self._session = None
        self._revision = None

    def sync(self, session):
        # A foreign session must not revoke or replace the current owner's
        # actor. This object owns one actor; callers need a separate instance
        # per session rather than allowing cross-session takeover.
        if self._actor is not None and session is not self._session:
            raise MovementError("movement belongs to another session")

        snapshot = session.snapshot
        if (snapshot.state is not SessionState.IN_MAP
                or snapshot.map_id != self._map
                or session.revision != self._revision):
            self._revoke()
        return self._actor

    def spawn(self, session, start, max_step):
        snapshot = session.snapshot
        self.sync(session)
        if snapshot.state is not SessionState.IN_MAP:
            raise MovementError("session is not in a map")
        if self._actor is not None:
            raise MovementError("actor already spawned")
        actor = MovementState(0, start, max_step)
        self._actor = actor
        self._map = snapshot.map_id
        self._session = session
        self._revision = session.revision
        return actor

    def move(self, session, tick, target):
        snapshot = session.snapshot
        if (session is not self._session
                or snapshot.state is not SessionState.IN_MAP
                or snapshot.map_id != self._map
                or session.revision != self._revision):
            self.sync(session)
            raise MovementError("session map is not active")
        if self._actor is None:
            raise MovementError("actor not spawned")
        return self._actor.move(0, tick, target)
