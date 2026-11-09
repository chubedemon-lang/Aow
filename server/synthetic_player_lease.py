"""In-memory synthetic player lease registry; not an AOW protocol implementation.

Prevents two local fixture connections from claiming the same player at once.
No persistence, wire format, or real APK identity semantics are assumed.
"""
from __future__ import annotations


class PlayerLeaseError(ValueError):
    """Invalid fixture ownership request or duplicate active lease."""


class PlayerLeaseRegistry:
    def __init__(self, max_players: int = 10000) -> None:
        if type(max_players) is not int or not 1 <= max_players <= 1000000:
            raise PlayerLeaseError("invalid capacity")
        self._max_players = max_players
        self._owners: dict[str, str] = {}
        self._players_by_connection: dict[str, str] = {}

    @staticmethod
    def _identifier(value: str) -> None:
        if type(value) is not str or not value.strip() or len(value) > 128 or not value.isprintable():
            raise PlayerLeaseError("invalid fixture identifier")

    def acquire(self, connection_id: str, player_id: str) -> None:
        self._identifier(connection_id)
        self._identifier(player_id)
        if connection_id in self._players_by_connection:
            raise PlayerLeaseError("connection already owns a player")
        if player_id in self._owners:
            raise PlayerLeaseError("player already leased")
        if len(self._owners) >= self._max_players:
            raise PlayerLeaseError("registry full")
        self._owners[player_id] = connection_id
        self._players_by_connection[connection_id] = player_id

    def release(self, connection_id: str) -> bool:
        self._identifier(connection_id)
        player_id = self._players_by_connection.pop(connection_id, None)
        if player_id is None:
            return False
        del self._owners[player_id]
        return True

    def owner_of(self, player_id: str) -> str | None:
        self._identifier(player_id)
        return self._owners.get(player_id)

    @property
    def active_count(self) -> int:
        return len(self._owners)
