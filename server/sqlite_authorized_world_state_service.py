"""Consistent authorized reads and movement snapshots for synthetic world state.

This is a local SQLite domain service only. It does not implement AOW player
initialization packets, map-join messages, transport framing or game rules.
The session/ownership check, optional map transition and all snapshot reads
share one BEGIN IMMEDIATE transaction, so revocation cannot interleave.
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
    MapPositionMutation,
    SqliteMapPositionStore,
)
from server.sqlite_player_state_store import SqlitePlayerStateStore
from server.synthetic_map_position import MapPosition
from server.synthetic_player_state import PlayerSnapshot
from server.sqlite_session_store import SqliteSessionStore


@dataclass(frozen=True)
class AuthorizedWorldSnapshot:
    """A consistent synthetic view of one owned character's durable state."""

    character: CharacterSnapshot
    player_state: PlayerSnapshot
    map_position: MapPosition


@dataclass(frozen=True)
class AuthorizedWorldMutationSnapshot:
    """A map-operation receipt plus the current world snapshot from one commit.

    On an idempotent retry, mutation.snapshot is the original receipt result,
    while snapshot is the latest committed world state. This distinction
    prevents a replay from pretending the character moved backwards when
    later transitions have already been committed.
    """

    mutation: MapPositionMutation
    snapshot: AuthorizedWorldSnapshot


class SqliteAuthorizedWorldStateService:
    """Read and transition synthetic character/player/map state atomically.

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

    @staticmethod
    def _validate_character_id(character_id: int) -> None:
        if (type(character_id) is not int
                or not 1 <= character_id <= 2**63 - 1):
            raise SessionError("invalid character")

    def _read_snapshot_in_transaction(self, owned_id: str,
                                       character_id: int) -> AuthorizedWorldSnapshot:
        """Read all world components; caller must hold the authorization lock."""
        row = self.db.execute(
            """SELECT id, name, map_id, x, y
               FROM characters WHERE id = ?""",
            (character_id,),
        ).fetchone()
        if row is None:
            # The ownership authorizer already checked this row while the same
            # write transaction is held; fail closed if data is inconsistent.
            raise SessionError("character not owned by session")

        character = CharacterSnapshot(
            character_id=int(row[0]),
            name=str(row[1]),
            map_id=str(row[2]),
            x=int(row[3]),
            y=int(row[4]),
        )
        return AuthorizedWorldSnapshot(
            character=character,
            player_state=self.players.get(owned_id),
            map_position=self.positions.get(owned_id),
        )

    def get_snapshot(self, token: str,
                     character_id: int) -> AuthorizedWorldSnapshot:
        """Return one coherent snapshot; reject missing or foreign state.

        BEGIN IMMEDIATE serializes the session/ownership check and all three
        reads with durable-session revocation and protected state mutations.
        """
        self._validate_character_id(character_id)
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._read_snapshot_in_transaction(owned_id, character_id)

    def _mutate_map_and_get_snapshot(
        self, token: str, character_id: int, mutation
    ) -> AuthorizedWorldMutationSnapshot:
        """Run a trusted store transition and read its committed view atomically."""
        self._validate_character_id(character_id)
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            result = mutation(owned_id)
            snapshot = self._read_snapshot_in_transaction(
                owned_id, character_id
            )
            return AuthorizedWorldMutationSnapshot(result, snapshot)

    def enter_and_get_snapshot(
        self, token: str, character_id: int, request_id: str,
        expected_revision: int, map_id: int, x: int, y: int,
    ) -> AuthorizedWorldMutationSnapshot:
        """Enter a synthetic map and return its world snapshot in one commit."""
        return self._mutate_map_and_get_snapshot(
            token,
            character_id,
            lambda owned_id: self.positions.enter(
                owned_id, request_id, expected_revision, map_id, x, y
            ),
        )

    def move_and_get_snapshot(
        self, token: str, character_id: int, request_id: str,
        expected_revision: int, map_id: int, x: int, y: int,
    ) -> AuthorizedWorldMutationSnapshot:
        """Move within a synthetic map and return the world snapshot atomically."""
        return self._mutate_map_and_get_snapshot(
            token,
            character_id,
            lambda owned_id: self.positions.move(
                owned_id, request_id, expected_revision, map_id, x, y
            ),
        )

    def leave_and_get_snapshot(
        self, token: str, character_id: int, request_id: str,
        expected_revision: int, map_id: int,
    ) -> AuthorizedWorldMutationSnapshot:
        """Leave a synthetic map and return the world snapshot in one commit."""
        return self._mutate_map_and_get_snapshot(
            token,
            character_id,
            lambda owned_id: self.positions.leave(
                owned_id, request_id, expected_revision, map_id
            ),
        )
