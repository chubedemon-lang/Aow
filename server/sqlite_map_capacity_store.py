"""Durable synthetic map-capacity projection for authorized local services.

This store coordinates configured map capacities across independent SQLite
connections/processes with BEGIN IMMEDIATE. It is a projection of the current
map_position_snapshots table, not an AOW map/room protocol or capacity claim.
"""
from contextlib import contextmanager
import sqlite3
import threading


_MAX_MAP_ID = 2**31 - 1
_MAX_CAPACITY = 100_000


class MapCapacityStoreError(ValueError):
    """Invalid or inconsistent durable synthetic map-capacity state."""


class MapCapacityExceeded(MapCapacityStoreError):
    """A configured synthetic map has no remaining capacity."""


class MapCapacityConfigurationError(MapCapacityStoreError):
    """A capacity change would invalidate existing synthetic occupancy."""


class SqliteMapCapacityStore:
    """Persist capacity limits and the current membership projection.

    One instance belongs to one caller-owned SQLite connection. Standalone
    writes use BEGIN IMMEDIATE; calls inside a caller transaction use a
    savepoint so the caller retains commit/rollback ownership.
    """

    def __init__(self, connection: sqlite3.Connection):
        if type(connection) is not sqlite3.Connection:
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self._lock = threading.RLock()
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute("PRAGMA foreign_keys = ON")
        if self.db.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise MapCapacityStoreError("SQLite foreign keys are disabled")
        parent = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name='map_position_snapshots'"
        ).fetchone()
        if parent != ("table",):
            raise MapCapacityStoreError("map-position store must be initialized first")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS map_capacity_limits (
                    map_id INTEGER PRIMARY KEY
                        CHECK(map_id BETWEEN 0 AND 2147483647),
                    capacity INTEGER NOT NULL
                        CHECK(capacity BETWEEN 1 AND 100000)
                )"""
            )
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS map_capacity_members (
                    character_id TEXT PRIMARY KEY
                        CHECK(length(character_id) BETWEEN 1 AND 128),
                    map_id INTEGER NOT NULL
                        CHECK(map_id BETWEEN 0 AND 2147483647),
                    FOREIGN KEY(character_id)
                        REFERENCES map_position_snapshots(character_id)
                        ON DELETE CASCADE
                )"""
            )
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS map_capacity_members_map "
                "ON map_capacity_members(map_id, character_id)"
            )
            self._validate_schema()
            self.db.commit()
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise

    @staticmethod
    def _map_id(value):
        if type(value) is not int or not 0 <= value <= _MAX_MAP_ID:
            raise MapCapacityStoreError("invalid map identifier")
        return value

    @staticmethod
    def _capacity(value):
        if type(value) is not int or not 1 <= value <= _MAX_CAPACITY:
            raise MapCapacityStoreError("invalid map capacity")
        return value

    @staticmethod
    def _character_id(value):
        if (type(value) is not str or not value or len(value) > 128
                or value != value.strip()):
            raise MapCapacityStoreError("invalid character identifier")
        return value

    def _validate_table_columns(self, table_name, expected):
        if type(table_name) is not str or table_name not in {
            "map_capacity_limits", "map_capacity_members"
        }:
            raise MapCapacityStoreError("invalid map-capacity table selector")
        table = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name=?", (table_name,)
        ).fetchone()
        if table != ("table",):
            raise MapCapacityStoreError("incompatible map-capacity table")
        rows = self.db.execute(
            "PRAGMA table_info(" + table_name + ")"
        ).fetchall()
        actual = {
            row[1]: (str(row[2]).strip().upper(), int(row[3]), int(row[5]), row[4])
            for row in rows
        }
        if len(rows) != len(expected) or actual != expected:
            raise MapCapacityStoreError("incompatible map-capacity schema")

    def _validate_schema(self):
        if self.db.execute("PRAGMA ignore_check_constraints").fetchone() != (0,):
            raise MapCapacityStoreError("SQLite CHECK constraints are disabled")
        self._validate_table_columns(
            "map_capacity_limits",
            {
                "map_id": ("INTEGER", 0, 1, None),
                "capacity": ("INTEGER", 1, 0, None),
            },
        )
        self._validate_table_columns(
            "map_capacity_members",
            {
                "character_id": ("TEXT", 0, 1, None),
                "map_id": ("INTEGER", 1, 0, None),
            },
        )
        if self.db.execute(
            "PRAGMA foreign_key_list(map_capacity_limits)"
        ).fetchall():
            raise MapCapacityStoreError("unexpected map-capacity limit foreign key")
        foreign_keys = self.db.execute(
            "PRAGMA foreign_key_list(map_capacity_members)"
        ).fetchall()
        actual_foreign_keys = tuple(
            (row[2], row[3], row[4], row[5], row[6], row[7])
            for row in foreign_keys
        )
        if actual_foreign_keys != ((
            "map_position_snapshots", "character_id", "character_id",
            "NO ACTION", "CASCADE", "NONE",
        ),):
            raise MapCapacityStoreError("incompatible map-capacity ownership foreign key")
        index_object = self.db.execute(
            "SELECT type, tbl_name FROM sqlite_master "
            "WHERE name='map_capacity_members_map'"
        ).fetchone()
        if index_object != ("index", "map_capacity_members"):
            raise MapCapacityStoreError("incompatible map-capacity index")
        indexes = [
            row for row in self.db.execute(
                "PRAGMA index_list(map_capacity_members)"
            ).fetchall()
            if row[1] == "map_capacity_members_map"
        ]
        if (len(indexes) != 1 or int(indexes[0][2]) != 0
                or indexes[0][3] != "c"
                or (len(indexes[0]) > 4 and int(indexes[0][4]) != 0)):
            raise MapCapacityStoreError("incompatible map-capacity index")
        columns = tuple(
            row[2] for row in self.db.execute(
                "PRAGMA index_info(map_capacity_members_map)"
            ).fetchall()
        )
        if columns != ("map_id", "character_id"):
            raise MapCapacityStoreError("incompatible map-capacity index")

        definitions = dict(self.db.execute(
            "SELECT name, sql FROM sqlite_master WHERE type='table' "
            "AND name IN (?, ?)",
            ("map_capacity_limits", "map_capacity_members"),
        ).fetchall())
        if set(definitions) != {"map_capacity_limits", "map_capacity_members"}:
            raise MapCapacityStoreError("incompatible map-capacity table definitions")
        if any(type(sql) is not str or "CHECK" not in sql.upper()
               for sql in definitions.values()):
            raise MapCapacityStoreError("missing map-capacity CHECK constraints")

    @contextmanager
    def _write_scope(self, savepoint_name):
        if savepoint_name not in (
            "map_capacity_configure", "map_capacity_reconcile"
        ):
            raise ValueError("invalid map-capacity savepoint")
        with self._lock:
            owns_transaction = not self.db.in_transaction
            if owns_transaction:
                self.db.execute("BEGIN IMMEDIATE")
            else:
                self.db.execute(f"SAVEPOINT {savepoint_name}")
            try:
                yield
                if owns_transaction:
                    self.db.commit()
                else:
                    self.db.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            except BaseException:
                if owns_transaction:
                    self.db.rollback()
                else:
                    self.db.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
                    self.db.execute(f"RELEASE SAVEPOINT {savepoint_name}")
                raise

    def configure_map(self, map_id: int, capacity: int) -> int:
        """Persist a limit and seed occupants already present on that map.

        Lowering a limit below current occupancy is rejected without changing
        the prior configuration. The operation is safe across SQLite writers.
        """
        map_id = self._map_id(map_id)
        capacity = self._capacity(capacity)
        with self._write_scope("map_capacity_configure"):
            occupants = self.db.execute(
                "SELECT character_id FROM map_position_snapshots WHERE map_id=? "
                "ORDER BY character_id",
                (map_id,),
            ).fetchall()
            if len(occupants) > capacity:
                raise MapCapacityConfigurationError(
                    "capacity is below current map occupancy"
                )
            self.db.execute(
                "INSERT INTO map_capacity_limits(map_id, capacity) VALUES (?, ?) "
                "ON CONFLICT(map_id) DO UPDATE SET capacity=excluded.capacity",
                (map_id, capacity),
            )
            # Rebuild this map's projection from authoritative position rows.
            self.db.execute(
                "DELETE FROM map_capacity_members WHERE map_id=?", (map_id,)
            )
            for (character_id,) in occupants:
                self._character_id(character_id)
                self.db.execute(
                    "INSERT INTO map_capacity_members(character_id, map_id) "
                    "VALUES (?, ?) ON CONFLICT(character_id) "
                    "DO UPDATE SET map_id=excluded.map_id",
                    (character_id, map_id),
                )
        return capacity

    def reconcile(self, character_id: str, map_id):
        """Synchronize one character's membership to its current position.

        map_id must exactly match the durable map-position snapshot. A map
        without a configured capacity is deliberately not tracked.
        Returns True only when the membership projection changed.
        """
        character_id = self._character_id(character_id)
        if map_id is not None:
            map_id = self._map_id(map_id)
        with self._write_scope("map_capacity_reconcile"):
            snapshot = self.db.execute(
                "SELECT map_id FROM map_position_snapshots WHERE character_id=?",
                (character_id,),
            ).fetchone()
            if snapshot is None:
                raise MapCapacityStoreError("map-position snapshot not found")
            stored_map_id = snapshot[0]
            if stored_map_id is not None and type(stored_map_id) is not int:
                raise MapCapacityStoreError("invalid stored map identifier")
            if stored_map_id != map_id:
                raise MapCapacityStoreError(
                    "capacity map does not match current position"
                )
            current = self.db.execute(
                "SELECT map_id FROM map_capacity_members WHERE character_id=?",
                (character_id,),
            ).fetchone()
            if map_id is None:
                if current is None:
                    return False
                self.db.execute(
                    "DELETE FROM map_capacity_members WHERE character_id=?",
                    (character_id,),
                )
                return True
            configured = self.db.execute(
                "SELECT capacity FROM map_capacity_limits WHERE map_id=?",
                (map_id,),
            ).fetchone()
            if configured is None:
                if current is None:
                    return False
                self.db.execute(
                    "DELETE FROM map_capacity_members WHERE character_id=?",
                    (character_id,),
                )
                return True
            limit = configured[0]
            if type(limit) is not int or not 1 <= limit <= _MAX_CAPACITY:
                raise MapCapacityStoreError("invalid stored map capacity")
            if current == (map_id,):
                return False
            occupied = self.db.execute(
                "SELECT count(*) FROM map_capacity_members WHERE map_id=? "
                "AND character_id<>?",
                (map_id, character_id),
            ).fetchone()[0]
            if occupied >= limit:
                raise MapCapacityExceeded("map capacity exceeded")
            self.db.execute(
                "INSERT INTO map_capacity_members(character_id, map_id) "
                "VALUES (?, ?) ON CONFLICT(character_id) "
                "DO UPDATE SET map_id=excluded.map_id",
                (character_id, map_id),
            )
            return True

    def capacity(self, map_id: int):
        map_id = self._map_id(map_id)
        with self._lock:
            row = self.db.execute(
                "SELECT capacity FROM map_capacity_limits WHERE map_id=?",
                (map_id,),
            ).fetchone()
            if row is None:
                return None
            if type(row[0]) is not int or not 1 <= row[0] <= _MAX_CAPACITY:
                raise MapCapacityStoreError("invalid stored map capacity")
            return row[0]

    def members(self, map_id: int):
        map_id = self._map_id(map_id)
        with self._lock:
            return frozenset(
                self._character_id(row[0]) for row in self.db.execute(
                    "SELECT character_id FROM map_capacity_members "
                    "WHERE map_id=? ORDER BY character_id",
                    (map_id,),
                ).fetchall()
            )

    def verify_integrity(self):
        """Check SQLite integrity and agreement with the position projection.

        The connection must be idle. This is diagnostic only; it never repairs
        rows and it does not authenticate ownership or infer AOW map semantics.
        """
        with self._lock:
            if self.db.in_transaction:
                raise ValueError("connection must not have an active transaction")
            self.db.execute("BEGIN")
            try:
                if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                    raise MapCapacityStoreError("SQLite quick_check failed")
                if self.db.execute("PRAGMA foreign_key_check").fetchall():
                    raise MapCapacityStoreError("map-capacity foreign key check failed")
                mismatched = self.db.execute(
                    """SELECT count(*) FROM map_capacity_members m
                       LEFT JOIN map_position_snapshots p
                         ON p.character_id=m.character_id
                       WHERE p.character_id IS NULL OR p.map_id IS NULL
                          OR p.map_id<>m.map_id"""
                ).fetchone()[0]
                missing = self.db.execute(
                    """SELECT count(*) FROM map_position_snapshots p
                       JOIN map_capacity_limits l ON l.map_id=p.map_id
                       LEFT JOIN map_capacity_members m
                         ON m.character_id=p.character_id AND m.map_id=p.map_id
                       WHERE p.map_id IS NOT NULL AND m.character_id IS NULL"""
                ).fetchone()[0]
                unconfigured = self.db.execute(
                    """SELECT count(*) FROM map_capacity_members m
                       LEFT JOIN map_capacity_limits l ON l.map_id=m.map_id
                       WHERE l.map_id IS NULL"""
                ).fetchone()[0]
                over_capacity = self.db.execute(
                    """SELECT count(*) FROM (
                           SELECT m.map_id, count(*) AS occupants, l.capacity
                           FROM map_capacity_members m
                           JOIN map_capacity_limits l ON l.map_id=m.map_id
                           GROUP BY m.map_id
                           HAVING occupants>l.capacity
                       )"""
                ).fetchone()[0]
                if mismatched or missing or unconfigured or over_capacity:
                    raise MapCapacityStoreError("map-capacity projection is inconsistent")
                members = self.db.execute(
                    "SELECT count(*) FROM map_capacity_members"
                ).fetchone()[0]
                maps = self.db.execute(
                    "SELECT count(*) FROM map_capacity_limits"
                ).fetchone()[0]
                return {"members": members, "configured_maps": maps}
            finally:
                if self.db.in_transaction:
                    self.db.rollback()
