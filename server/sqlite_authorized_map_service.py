"""Session-authorized facade for the synthetic SQLite map-position store.

This is a local server-domain integration only. It is NOT the AOW APK login
protocol, does not authenticate passwords, and does not establish character
or map semantics from the original game.

The connection must already contain the repository's synthetic
`characters(id, account_id)` ownership table. Session tokens must only be
issued after a trusted authentication layer has verified the account.
"""
import sqlite3

from server.sqlite_character_authorizer import SqliteCharacterAuthorizer
from server.sqlite_map_position_store import (
    MapPositionMutation,
    SqliteMapPositionStore,
)
from server.sqlite_session_store import SqliteSessionStore
from server.synthetic_map_position import MapPosition


class SqliteAuthorizedMapService:
    """Authorize every map operation against a durable synthetic session.

    No HTTP route is registered here. Callers remain responsible for trusted
    account authentication before issuing a session via `sessions.issue()`.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self.positions = SqliteMapPositionStore(connection)

    def create_position(self, token: str, character_id: int) -> MapPosition:
        """Create the initial unplaced snapshot for an owned character."""
        owned_id = self.authorizer.require(token, character_id)
        return self.positions.create(owned_id)

    def get_position(self, token: str, character_id: int) -> MapPosition:
        """Read a position only after resolving and checking session ownership."""
        owned_id = self.authorizer.require(token, character_id)
        return self.positions.get(owned_id)

    def enter(self, token: str, character_id: int, request_id: str,
              expected_revision: int, map_id: int, x: int, y: int
              ) -> MapPositionMutation:
        owned_id = self.authorizer.require(token, character_id)
        return self.positions.enter(
            owned_id, request_id, expected_revision, map_id, x, y
        )

    def move(self, token: str, character_id: int, request_id: str,
             expected_revision: int, map_id: int, x: int, y: int
             ) -> MapPositionMutation:
        owned_id = self.authorizer.require(token, character_id)
        return self.positions.move(
            owned_id, request_id, expected_revision, map_id, x, y
        )

    def leave(self, token: str, character_id: int, request_id: str,
              expected_revision: int, map_id: int
              ) -> MapPositionMutation:
        owned_id = self.authorizer.require(token, character_id)
        return self.positions.leave(
            owned_id, request_id, expected_revision, map_id
        )
