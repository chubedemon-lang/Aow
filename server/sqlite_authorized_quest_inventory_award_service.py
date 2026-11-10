"""Session-authorized atomic synthetic quest-to-inventory awards.

The trusted quest domain must validate completion before calling grant_once.
This facade does not implement AOW quest rules or packets and is not exposed as
an HTTP route. Durable session authorization, character ownership, inventory
mutation and the unique quest-award receipt share one BEGIN IMMEDIATE
transaction so session revocation cannot race the grant.
"""
import sqlite3

from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_quest_inventory_award_store import (
    QuestInventoryAward,
    SqliteQuestInventoryAwardStore,
)
from server.sqlite_session_store import SqliteSessionStore


_MAX_TTL_SECONDS = 31_536_000


class SqliteAuthorizedQuestInventoryAwardService:
    """Authorize and atomically grant one synthetic quest item into inventory."""

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        require_character_schema(connection)
        if (type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS):
            raise ValueError("invalid session ttl")

        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self._inventory = SqliteInventoryStore(connection)
        self._awards = SqliteQuestInventoryAwardStore(
            connection, self._inventory
        )

    def grant_once(self, token: str, character_id: int, request_id: str,
                   expected_inventory_revision: int, quest_id: int,
                   item_id: str, quantity: int) -> QuestInventoryAward:
        """Grant after trusted quest completion validation; exact retries are safe."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._awards.grant_once(
                owned_id, request_id, expected_inventory_revision,
                quest_id, item_id, quantity,
            )
