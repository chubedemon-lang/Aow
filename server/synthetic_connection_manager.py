"""Atomic synthetic connection/session and player-lease coordination.

Offline server fixture only. No AOW APK protocol or identity compatibility claim.
"""
from __future__ import annotations

from server.synthetic_connection_gate import ConnectionGate
from server.synthetic_player_lease import PlayerLeaseRegistry
from server.synthetic_session import SessionError, Phase


class SyntheticConnectionManager:
    """Coordinates leases with local session state; caller supplies trusted fixture IDs."""

    def __init__(self, max_players: int = 10000) -> None:
        self.leases = PlayerLeaseRegistry(max_players)
        self._connections: dict[str, ConnectionGate] = {}

    def open(self, connection_id: str) -> ConnectionGate:
        self.leases._identifier(connection_id)
        if connection_id in self._connections:
            raise SessionError("connection already open")
        gate = ConnectionGate()
        self._connections[connection_id] = gate
        return gate

    def select_player(self, connection_id: str, player_id: str) -> None:
        gate = self._get(connection_id)
        if gate.session.phase is not Phase.AUTHENTICATED:
            raise SessionError("connection must be authenticated")
        self.leases.acquire(connection_id, player_id)
        try:
            gate.select_player(player_id)
        except Exception:
            self.leases.release(connection_id)
            raise

    def _get(self, connection_id: str) -> ConnectionGate:
        self.leases._identifier(connection_id)
        try:
            return self._connections[connection_id]
        except KeyError as exc:
            raise SessionError("unknown connection") from exc

    def close(self, connection_id: str) -> bool:
        self.leases._identifier(connection_id)
        gate = self._connections.pop(connection_id, None)
        if gate is None:
            return False
        try:
            gate.close()
        finally:
            self.leases.release(connection_id)
        return True

    @property
    def active_connections(self) -> int:
        return len(self._connections)
