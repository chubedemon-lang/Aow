"""Thread-safe synthetic connection/session and player-lease coordination.

Offline server fixture only. No AOW APK protocol or identity compatibility claim.
"""
from __future__ import annotations

from threading import RLock

from server.synthetic_connection_gate import ConnectionGate
from server.synthetic_player_lease import PlayerLeaseRegistry
from server.synthetic_session import SessionError, Phase


class SyntheticConnectionManager:
    """Coordinates fixture sessions and leases within one process."""

    def __init__(self, max_players: int = 10000) -> None:
        self.leases = PlayerLeaseRegistry(max_players)
        self._connections: dict[str, ConnectionGate] = {}
        self._lock = RLock()

    def open(self, connection_id: str) -> ConnectionGate:
        with self._lock:
            self.leases._identifier(connection_id)
            if connection_id in self._connections:
                raise SessionError("connection already open")
            gate = ConnectionGate()
            self._connections[connection_id] = gate
            return gate

    def select_player(self, connection_id: str, player_id: str) -> None:
        with self._lock:
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
        with self._lock:
            self.leases._identifier(connection_id)
            try:
                return self._connections[connection_id]
            except KeyError as exc:
                raise SessionError("unknown connection") from exc

    def close(self, connection_id: str) -> bool:
        with self._lock:
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
        with self._lock:
            return len(self._connections)
