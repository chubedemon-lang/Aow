"""Session-authorized facade for synthetic durable player progression.

This is a local server-domain integration only. It does not implement AOW
login, player initialization packets, or original-game progression rules.
Session tokens must only be issued after trusted account authentication.
No HTTP route is registered by this facade.

Every operation holds BEGIN IMMEDIATE across session resolution, character
ownership and player persistence so revocation cannot race a protected change.
"""
import sqlite3

from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_player_state_store import (
    PlayerMutation,
    PlayerSnapshot,
    SqlitePlayerStateStore,
)
from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedPlayerStateService:
    """Authorize every player snapshot operation against a durable session."""

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
        self.players = SqlitePlayerStateStore(connection)

    def create_snapshot(self, token: str, character_id: int, *,
                        level: int = 1, experience: int = 0,
                        currency: int = 0) -> PlayerSnapshot:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.players.create(
                owned_id, level=level, experience=experience, currency=currency
            )

    def get_snapshot(self, token: str, character_id: int) -> PlayerSnapshot:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.players.get(owned_id)

    def apply(self, token: str, character_id: int, request_id: str,
              expected_revision: int, *, level=None,
              experience_delta: int = 0,
              currency_delta: int = 0) -> PlayerMutation:
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self.players.apply(
                owned_id, request_id, expected_revision,
                level=level,
                experience_delta=experience_delta,
                currency_delta=currency_delta,
            )
