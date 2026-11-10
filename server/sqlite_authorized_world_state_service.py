"""Consistent authorized reads of synthetic character, player and map state.

This is a local SQLite domain service only. It does not implement AOW player
initialization packets, map-join messages, transport framing or game rules.
The read holds the same BEGIN IMMEDIATE authorization boundary used by
protected mutations, so session revocation cannot interleave between ownership
validation and the three related snapshot reads.
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
from server.sqlite_map_position_store import (
    MapPosition,
    MapPositionNotFound,
    SqliteMapPositionStore,
)
from server.sqlite_player_state_store import (
    PlayerSnapshot,
    PlayerNotFound,
    SqlitePlayerStateStore,
)
from server.sqlite_session_store import SqliteSessionStore


@dataclass(frozen=True)
class AuthorizedWorldSnapshot:
    """A consistent synthetic view of one owned character's durable state."""

    character: CharacterSnapshot
    player_state: PlayerSnapshot
    map_position: MapPosition


class SqliteAuthorizedWorldStateService:
    """Read character, player and map state under one session/ownership check.

    The service requires the initialized synthetic accounts/characters/wallets
    schema. It creates only the auxiliary player/map persistence tables when
    absent. Reads do not create missing per-character snapshots or repair data.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        require_character_lifecycle_schema(connection)
        connection.execute("PRAGMA foreign_keys = ON")

        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self.players = SqlitePlayerStateStore(connection)
        self.positions = SqliteMapPositionStore(connection)

    def get_snapshot(self, token: str,
                     character_id: int) -> AuthorizedWorldSnapshot:
        """Return one coherent snapshot; reject missing or foreign state.

        BEGIN IMMEDIATE is intentional: the session/ownership check and all
        three reads share one SQLite transaction, serializing this operation
        with durable-session revocation and protected state mutations.
        """
        if (type(character_id) is not int
                or not 1 <= character_id <= 2**63 - 1):
            raise SessionError("invalid character")

        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            row = self.db.execute(
                """SELECT id, name, map_id, x, y
                   FROM characters WHERE id = ?""",
                (character_id,),
            ).fetchone()
            if row is None:
                # The ownership authorizer already checked this row while the
                # same write transaction is held; fail closed if schema/data
                # changes unexpectedly within the transaction.
                raise SessionError("character not owned by session")

            character = CharacterSnapshot(
                character_id=int(row[0]),
                name=str(row[1]),
                map_id=str(row[2]),
                x=int(row[3]),
                y=int(row[4]),
            )
            player_state = self.players.get(owned_id)
            map_position = self.positions.get(owned_id)
            return AuthorizedWorldSnapshot(
                character=character,
                player_state=player_state,
                map_position=map_position,
            )
