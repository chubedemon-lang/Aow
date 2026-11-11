"""One-transaction authorized synthetic player bootstrap snapshot.

This is a local domain read model, not an AOW player-initialization packet or
wire contract. It combines character, player, map-position and inventory
snapshots under the same session/ownership transaction so callers cannot see
a mixed revision while another protected operation or session revocation runs.
"""
from dataclasses import dataclass
import sqlite3

from server.sessions import SessionError
from server.sqlite_authorized_character_service import (
    CharacterSnapshot,
    require_character_lifecycle_schema,
)
from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import SqliteCharacterAuthorizer
from server.sqlite_inventory_store import InventorySnapshot, SqliteInventoryStore
from server.sqlite_map_position_store import SqliteMapPositionStore
from server.sqlite_player_state_store import SqlitePlayerStateStore
from server.sqlite_session_store import SqliteSessionStore
from server.synthetic_map_position import MapPosition
from server.synthetic_player_state import PlayerSnapshot


@dataclass(frozen=True)
class AuthorizedPlayerBootstrapSnapshot:
    """Coherent synthetic state needed by a future player-bootstrap adapter."""

    character: CharacterSnapshot
    player_state: PlayerSnapshot
    map_position: MapPosition
    inventory: InventorySnapshot


class SqliteAuthorizedPlayerBootstrapService:
    """Read all initialized player domains with one authorization boundary.

    Store constructors create missing auxiliary tables, but get_snapshot()
    never creates or repairs per-character rows. Missing player, map or
    inventory snapshots fail closed. All returned components are read while
    one BEGIN IMMEDIATE transaction holds the session/ownership boundary.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        require_character_lifecycle_schema(connection)

        self.db = connection
        self.db.execute("PRAGMA foreign_keys = ON")
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self.players = SqlitePlayerStateStore(connection)
        self.positions = SqliteMapPositionStore(connection)
        self.inventories = SqliteInventoryStore(connection)

    @staticmethod
    def _validate_character_id(character_id: int) -> None:
        if (type(character_id) is not int
                or not 1 <= character_id <= 2**63 - 1):
            raise SessionError("invalid character")

    def get_snapshot(
        self, token: str, character_id: int
    ) -> AuthorizedPlayerBootstrapSnapshot:
        """Return one coherent, read-only per-character bootstrap snapshot.

        The transaction is intentionally held across every component read.
        BEGIN IMMEDIATE serializes this read with durable-session revocation
        and the repository's protected SQLite domain mutations.
        """
        self._validate_character_id(character_id)
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            row = self.db.execute(
                """SELECT id, name, map_id, x, y
                   FROM characters WHERE id = ?""",
                (character_id,),
            ).fetchone()
            if row is None:
                # Ownership was checked in this same transaction. Fail closed
                # if the character row is inconsistent or disappears.
                raise SessionError("character not owned by session")

            character = CharacterSnapshot(
                character_id=int(row[0]),
                name=str(row[1]),
                map_id=str(row[2]),
                x=int(row[3]),
                y=int(row[4]),
            )
            return AuthorizedPlayerBootstrapSnapshot(
                character=character,
                player_state=self.players.get(owned_id),
                map_position=self.positions.get(owned_id),
                inventory=self.inventories.get(owned_id),
            )
