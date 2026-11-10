"""Session-authorized facade for synthetic durable SQLite inventories.

This is a local server-domain integration only. It does not implement AOW
inventory packets, item catalogs, equipment rules, or original-game semantics.
Item IDs and inventory limits remain synthetic caller-supplied values.

Every operation holds one BEGIN IMMEDIATE transaction across session
resolution, character ownership and the underlying inventory operation. This
serializes session revocation with inventory reads and mutations.
"""
import sqlite3

from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_inventory_store import (
    InventoryMutation,
    InventorySnapshot,
    SqliteInventoryStore,
)
from server.sqlite_session_store import SqliteSessionStore


_MAX_TTL_SECONDS = 31_536_000


class SqliteAuthorizedInventoryService:
    """Require an active session and character ownership for every operation."""

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        # Fail before creating session or inventory tables on an uninitialized DB.
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

    def create(self, token: str, character_id: int, *,
               capacity: int = 20,
               max_stack: int = 99) -> InventorySnapshot:
        """Create an inventory atomically with its session authorization."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._inventory.create(
                owned_id, capacity=capacity, max_stack=max_stack
            )

    def get(self, token: str, character_id: int) -> InventorySnapshot:
        """Read an inventory while holding the authorization transaction."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._inventory.get(owned_id)

    def apply(self, token: str, character_id: int, request_id: str,
              expected_revision: int, changes) -> InventoryMutation:
        """Apply item deltas once; authorization and receipt replay are atomic."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._inventory.apply(
                owned_id, request_id, expected_revision, changes
            )
