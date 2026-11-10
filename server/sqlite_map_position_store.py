"""Durable synthetic map positions; not an AOW map or movement contract.

Map identifiers, coordinate units and transition rules are caller-supplied
synthetic values. Each transition is revision-guarded and has a durable,
idempotent receipt. This store does not authenticate character ownership.
"""
import json
import sqlite3
from dataclasses import dataclass
from typing import Callable

from server.synthetic_map_position import MapPosition, MapPositionError, Position


_MAX_REVISION = 2**63 - 1
_MAX_MAP_ID = 2**31 - 1


class MapPositionStoreError(ValueError):
    """Invalid or inconsistent synthetic map-position state."""


class MapPositionNotFound(MapPositionStoreError):
    """No map-position snapshot exists for the character."""


class MapPositionAlreadyExists(MapPositionStoreError):
    """A map-position snapshot already exists for the character."""


class MapPositionRevisionConflict(MapPositionStoreError):
    """The expected map-position revision is stale."""


class MapPositionOperationConflict(MapPositionStoreError):
    """An idempotency key was reused for a different transition."""


@dataclass(frozen=True)
class MapPositionMutation:
    snapshot: MapPosition
    replayed: bool


class SqliteMapPositionStore:
    """SQLite-backed synthetic map position snapshots.

    Every enter/move/leave transition and its receipt commit in one
    BEGIN IMMEDIATE transaction. The supplied connection must be idle
    before construction and before every mutation.
    """

    def __init__(self, connection: sqlite3.Connection):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS map_position_snapshots (
                character_id TEXT PRIMARY KEY
                    CHECK(length(character_id) BETWEEN 1 AND 128),
                map_id INTEGER,
                x INTEGER,
                y INTEGER,
                revision INTEGER NOT NULL
                    CHECK(revision BETWEEN 0 AND 9223372036854775807),
                CHECK(
                    (map_id IS NULL AND x IS NULL AND y IS NULL)
                    OR
                    (map_id BETWEEN 0 AND 2147483647
                     AND x BETWEEN -2147483648 AND 2147483647
                     AND y BETWEEN -2147483648 AND 2147483647)
                )
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS map_position_mutations (
                request_id TEXT PRIMARY KEY
                    CHECK(length(request_id) BETWEEN 1 AND 128),
                character_id TEXT NOT NULL,
                expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_revision INTEGER NOT NULL CHECK(result_revision > 0),
                FOREIGN KEY(character_id)
                    REFERENCES map_position_snapshots(character_id)
                    ON DELETE CASCADE
            )"""
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS map_position_mutations_character "
            "ON map_position_mutations(character_id, result_revision)"
        )
        self.db.commit()

    @staticmethod
    def _character_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise MapPositionStoreError("invalid character identifier")
        return value

    @staticmethod
    def _request_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise MapPositionStoreError("invalid request identifier")
        return value

    @staticmethod
    def _expected_revision(value):
        if type(value) is not int or not 0 <= value < _MAX_REVISION:
            raise MapPositionStoreError("invalid expected revision")
        return value

    @staticmethod
    def _map_id(value):
        if type(value) is not int or not 0 <= value <= _MAX_MAP_ID:
            raise MapPositionStoreError("invalid map identifier")
        return value

    @staticmethod
    def _position(x, y):
        try:
            return Position(x, y)
        except MapPositionError as exc:
            raise MapPositionStoreError("invalid position") from exc

    @staticmethod
    def _snapshot(row):
        map_id, x, y, revision = row
        position = None if map_id is None else Position(int(x), int(y))
        return MapPosition(
            map_id=None if map_id is None else int(map_id),
            position=position,
            revision=int(revision),
        )

    @staticmethod
    def _encode_snapshot(snapshot):
        return json.dumps(
            {
                "map_id": snapshot.map_id,
                "x": None if snapshot.position is None else snapshot.position.x,
                "y": None if snapshot.position is None else snapshot.position.y,
                "revision": snapshot.revision,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    @staticmethod
    def _decode_snapshot(raw):
        value = json.loads(raw)
        map_id = value["map_id"]
        position = None if map_id is None else Position(value["x"], value["y"])
        return MapPosition(
            map_id=map_id,
            position=position,
            revision=value["revision"],
        )

    def create(self, character_id: str) -> MapPosition:
        character_id = self._character_id(character_id)
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            try:
                self.db.execute(
                    """INSERT INTO map_position_snapshots
                       (character_id, map_id, x, y, revision)
                       VALUES (?, NULL, NULL, NULL, 0)""",
                    (character_id,),
                )
            except sqlite3.IntegrityError as exc:
                raise MapPositionAlreadyExists(
                    "map-position snapshot already exists"
                ) from exc
            self.db.commit()
            return MapPosition()
        except BaseException:
            self.db.rollback()
            raise

    def get(self, character_id: str) -> MapPosition:
        character_id = self._character_id(character_id)
        row = self.db.execute(
            """SELECT map_id, x, y, revision
               FROM map_position_snapshots WHERE character_id=?""",
            (character_id,),
        ).fetchone()
        if row is None:
            raise MapPositionNotFound("map-position snapshot not found")
        return self._snapshot(row)

    def _mutate(self, character_id, request_id, expected_revision,
                operation, payload, transition: Callable[[MapPosition], MapPosition]):
        character_id = self._character_id(character_id)
        request_id = self._request_id(request_id)
        expected_revision = self._expected_revision(expected_revision)
        payload_json = json.dumps(
            {"operation": operation, **payload},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                """SELECT character_id, expected_revision, payload_json, result_json
                   FROM map_position_mutations WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:3]) != (
                    character_id, expected_revision, payload_json
                ):
                    raise MapPositionOperationConflict(
                        "request id reused with a different map transition"
                    )
                snapshot = self._decode_snapshot(previous[3])
                self.db.commit()
                return MapPositionMutation(snapshot, True)

            row = self.db.execute(
                """SELECT map_id, x, y, revision
                   FROM map_position_snapshots WHERE character_id=?""",
                (character_id,),
            ).fetchone()
            if row is None:
                raise MapPositionNotFound("map-position snapshot not found")
            current = self._snapshot(row)
            if current.revision != expected_revision:
                raise MapPositionRevisionConflict("stale map-position revision")
            if current.revision >= _MAX_REVISION:
                raise MapPositionStoreError("map-position revision overflow")

            updated = transition(current)
            if (not isinstance(updated, MapPosition)
                    or updated.revision != current.revision + 1):
                raise MapPositionStoreError("invalid map-position transition")

            x = None if updated.position is None else updated.position.x
            y = None if updated.position is None else updated.position.y
            cursor = self.db.execute(
                """UPDATE map_position_snapshots
                   SET map_id=?, x=?, y=?, revision=?
                   WHERE character_id=? AND revision=?""",
                (updated.map_id, x, y, updated.revision,
                 character_id, current.revision),
            )
            if cursor.rowcount != 1:
                raise MapPositionRevisionConflict("map-position changed concurrently")

            self.db.execute(
                """INSERT INTO map_position_mutations
                   (request_id, character_id, expected_revision, payload_json,
                    result_json, result_revision)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (request_id, character_id, expected_revision, payload_json,
                 self._encode_snapshot(updated), updated.revision),
            )
            self.db.commit()
            return MapPositionMutation(updated, False)
        except MapPositionError as exc:
            self.db.rollback()
            raise MapPositionStoreError(str(exc)) from exc
        except BaseException:
            self.db.rollback()
            raise

    def enter(self, character_id: str, request_id: str, expected_revision: int,
              map_id: int, x: int, y: int) -> MapPositionMutation:
        map_id = self._map_id(map_id)
        position = self._position(x, y)
        return self._mutate(
            character_id, request_id, expected_revision, "enter",
            {"map_id": map_id, "x": position.x, "y": position.y},
            lambda current: current.enter(map_id, position),
        )

    def move(self, character_id: str, request_id: str, expected_revision: int,
             map_id: int, x: int, y: int) -> MapPositionMutation:
        map_id = self._map_id(map_id)
        position = self._position(x, y)

        def transition(current):
            if current.map_id != map_id:
                raise MapPositionStoreError("character is not in the expected map")
            return current.move(position, expected_revision)

        return self._mutate(
            character_id, request_id, expected_revision, "move",
            {"map_id": map_id, "x": position.x, "y": position.y},
            transition,
        )

    def leave(self, character_id: str, request_id: str, expected_revision: int,
              map_id: int) -> MapPositionMutation:
        map_id = self._map_id(map_id)

        def transition(current):
            if current.map_id != map_id:
                raise MapPositionStoreError("character is not in the expected map")
            return current.leave()

        return self._mutate(
            character_id, request_id, expected_revision, "leave",
            {"map_id": map_id},
            transition,
        )
