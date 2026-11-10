"""Session-authorized facade for synthetic durable SQLite inventories.

This is a local server-domain integration only. It does not implement AOW
inventory packets, item catalogs, equipment rules, or original-game semantics.
Item IDs and inventory limits remain synthetic caller-supplied values.

Session tokens must only be issued after a trusted authentication layer has
verified the account. No HTTP route is registered by this facade. Character
ownership transfer is not supported; if added, it must be serialized with
inventory mutations and authorization.
"""
import sqlite3

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
        """Create an inventory only for a character owned by the active session."""
        owned_id = self.authorizer.require(token, character_id)
        return self._inventory.create(
            owned_id, capacity=capacity, max_stack=max_stack
        )

    def get(self, token: str, character_id: int) -> InventorySnapshot:
        """Read an inventory only after resolving session ownership."""
        owned_id = self.authorizer.require(token, character_id)
        return self._inventory.get(owned_id)

    def apply(self, token: str, character_id: int, request_id: str,
              expected_revision: int, changes) -> InventoryMutation:
        """Apply item deltas once; authorization is repeated before receipt replay."""
        owned_id = self.authorizer.require(token, character_id)
        return self._inventory.apply(
            owned_id, request_id, expected_revision, changes
        )
