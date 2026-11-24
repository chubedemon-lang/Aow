"""Synthetic per-session player profile; no AOW APK field or wire claims.

Profiles are intentionally ephemeral and scoped to a selected character and
its owning Session object, including across verified connection handoffs.
"""
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from .synthetic_session_state import Phase


class PlayerProfileError(ValueError):
    pass


@dataclass(frozen=True)
class PlayerProfile:
    character_id: str
    level: int
    experience: int
    health: int
    max_health: int


class PlayerProfiles:
    def __init__(self):
        self._profiles = WeakKeyDictionary()

    @staticmethod
    def _session(registry, connection_id):
        session = registry.get(connection_id)
        snap = session.snapshot
        if snap.phase not in (Phase.CHARACTER_SELECTED, Phase.IN_MAP):
            raise PlayerProfileError("character not selected")
        return session, snap

    def initialize(self, registry, connection_id, *, level=1, max_health=100):
        session, snap = self._session(registry, connection_id)
        if type(level) is not int or not 1 <= level <= 1000:
            raise PlayerProfileError("invalid level")
        if type(max_health) is not int or not 1 <= max_health <= 1000000:
            raise PlayerProfileError("invalid max health")
        existing = self._profiles.get(session)
        if existing is not None and existing.character_id == snap.character_id:
            raise PlayerProfileError("profile already initialized")
        profile = PlayerProfile(snap.character_id, level, 0, max_health, max_health)
        self._profiles[session] = profile
        return profile

    def get(self, registry, connection_id):
        session, snap = self._session(registry, connection_id)
        profile = self._profiles.get(session)
        if profile is None or profile.character_id != snap.character_id:
            raise PlayerProfileError("profile not initialized")
        return profile

    def set_health(self, registry, connection_id, health):
        profile = self.get(registry, connection_id)
        if type(health) is not int or not 0 <= health <= profile.max_health:
            raise PlayerProfileError("invalid health")
        session = registry.get(connection_id)
        updated = PlayerProfile(profile.character_id, profile.level,
                                profile.experience, health, profile.max_health)
        self._profiles[session] = updated
        return updated

    def grant_experience(self, registry, connection_id, amount):
        profile = self.get(registry, connection_id)
        if type(amount) is not int or not 1 <= amount <= 1000000:
            raise PlayerProfileError("invalid experience amount")
        if profile.experience + amount > 2**63 - 1:
            raise PlayerProfileError("experience overflow")
        session = registry.get(connection_id)
        updated = PlayerProfile(profile.character_id, profile.level,
                                profile.experience + amount, profile.health,
                                profile.max_health)
        self._profiles[session] = updated
        return updated

    def forget(self, session):
        self._profiles.pop(session, None)
