"""Session-authorized facade for synthetic durable map positions.

This is a local server-domain integration only. It does not implement AOW
login, map identifiers, movement packets, coordinate units, or client rules.
Every operation holds BEGIN IMMEDIATE across session resolution, character
ownership and map-position persistence so revocation cannot race a mutation.
Session tokens must only be issued after trusted account authentication.
No HTTP route is registered here; ownership transfer is not supported.
"""
import sqlite3

from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_map_position_store import (
    MapPositionMutation,
    SqliteMapPositionStore,
)
from server.sqlite_session_store import SqliteSessionStore
from server.synthetic_map_position import MapPosition


class SqliteAuthorizedMapPositionService:
    """Authorize every durable map-position operation against a session."""

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        require_character_schema(connection)
        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self.positions = SqliteMapPositionStore(connection)

    def create_position(self, token: str, character_id: int) -> MapPosition:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.positions.create(owned_id)

    def get_position(self, token: str, character_id: int) -> MapPosition:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.positions.get(owned_id)

    def enter_map(self, token: str, character_id: int, request_id: str,
                  expected_revision: int, map_id: int, x: int,
                  y: int) -> MapPositionMutation:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.positions.enter(
                owned_id, request_id, expected_revision, map_id, x, y
            )

    def move(self, token: str, character_id: int, request_id: str,
             expected_revision: int, map_id: int, x: int,
             y: int) -> MapPositionMutation:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.positions.move(
                owned_id, request_id, expected_revision, map_id, x, y
            )

    def leave_map(self, token: str, character_id: int, request_id: str,
                  expected_revision: int, map_id: int) -> MapPositionMutation:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.positions.leave(
                owned_id, request_id, expected_revision, map_id
            )
