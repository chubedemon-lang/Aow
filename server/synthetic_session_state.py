"""Local-only synthetic session state machine; NOT the AOW wire protocol.

A bounded domain primitive for future adapters after authorized offline evidence.
When owned by SessionRegistry, public transitions are routed back through that
registry so its locking and uniqueness checks cannot be bypassed accidentally.
"""
from dataclasses import dataclass
from enum import Enum


class SessionError(ValueError):
    pass


class Phase(str, Enum):
    NEW = "new"
    AUTHENTICATED = "authenticated"
    CHARACTER_SELECTED = "character_selected"
    IN_MAP = "in_map"
    CLOSED = "closed"


@dataclass(frozen=True)
class Snapshot:
    phase: Phase
    account_id: str | None
    character_id: str | None
    map_id: int | None


class Session:
    def __init__(self):
        self._snapshot = Snapshot(Phase.NEW, None, None, None)
        self._transition_handler = None

    @property
    def snapshot(self):
        return self._snapshot

    def _bind_transition_handler(self, handler):
        """Bind registry-owned sessions to their serialized transition owner."""
        self._transition_handler = handler

    def _dispatch(self, operation, *args):
        if self._transition_handler is not None:
            return self._transition_handler(operation, *args)
        return getattr(self, "_" + operation + "_unchecked")(*args)

    @staticmethod
    def _identifier(value):
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.strip():
            raise SessionError("invalid identifier")
        return value

    def authenticate(self, account_id):
        return self._dispatch("authenticate", account_id)

    def _authenticate_unchecked(self, account_id):
        if self._snapshot.phase is not Phase.NEW:
            raise SessionError("authentication not allowed")
        self._snapshot = Snapshot(Phase.AUTHENTICATED, self._identifier(account_id), None, None)

    def select_character(self, character_id):
        return self._dispatch("select_character", character_id)

    def _select_character_unchecked(self, character_id):
        if self._snapshot.phase is not Phase.AUTHENTICATED:
            raise SessionError("character selection not allowed")
        self._snapshot = Snapshot(Phase.CHARACTER_SELECTED, self._snapshot.account_id,
                                  self._identifier(character_id), None)

    def join_map(self, map_id):
        return self._dispatch("join_map", map_id)

    def _join_map_unchecked(self, map_id):
        if self._snapshot.phase is not Phase.CHARACTER_SELECTED:
            raise SessionError("map join not allowed")
        if type(map_id) is not int or not 0 <= map_id <= 2**31 - 1:
            raise SessionError("invalid map identifier")
        self._snapshot = Snapshot(Phase.IN_MAP, self._snapshot.account_id,
                                  self._snapshot.character_id, map_id)

    def leave_map(self):
        return self._dispatch("leave_map")

    def _leave_map_unchecked(self):
        if self._snapshot.phase is not Phase.IN_MAP:
            raise SessionError("map leave not allowed")
        self._snapshot = Snapshot(Phase.CHARACTER_SELECTED, self._snapshot.account_id,
                                  self._snapshot.character_id, None)

    def close(self):
        return self._dispatch("close")

    def _close_unchecked(self):
        self._snapshot = Snapshot(Phase.CLOSED, None, None, None)
        self._transition_handler = None
