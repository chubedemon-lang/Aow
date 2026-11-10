"""Durable synthetic inventory snapshots; not an AOW item or wire contract.

Item identifiers, capacities and stack limits are caller-supplied synthetic
domain values. The store provides atomic revision-guarded mutations and
idempotent receipts; it does not infer the original game's inventory rules.
"""
import json
import re
import sqlite3
from dataclasses import dataclass


_MAX_CAPACITY = 4096
_MAX_STACK = 2**31 - 1
_MAX_REVISION = 2**63 - 1
_MAX_BATCH = 4096
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class InventoryStoreError(ValueError):
    """Invalid or inconsistent synthetic inventory state."""


class InventoryNotFound(InventoryStoreError):
    """No inventory exists for the requested character."""


class InventoryAlreadyExists(InventoryStoreError):
    """An inventory already exists for the requested character."""


class InventoryRevisionConflict(InventoryStoreError):
    """The caller's expected inventory revision is stale."""


class InventoryOperationConflict(InventoryStoreError):
    """An idempotency key was reused with a different operation."""


@dataclass(frozen=True)
class InventorySnapshot:
    character_id: str
    capacity: int
    max_stack: int
    revision: int
    items: tuple

    def count(self, item_id: str) -> int:
        for current_id, quantity in self.items:
            if current_id == item_id:
                return quantity
        return 0


@dataclass(frozen=True)
class InventoryMutation:
    snapshot: InventorySnapshot
    replayed: bool


class SqliteInventoryStore:
    """SQLite inventory snapshots with optimistic revisions and idempotency.

    Mutations and their receipts commit in one BEGIN IMMEDIATE transaction.
    The supplied connection must be idle before construction and mutation.
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
            """CREATE TABLE IF NOT EXISTS inventory_snapshots (
                character_id TEXT PRIMARY KEY
                    CHECK(length(character_id) BETWEEN 1 AND 128),
                capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1 AND 4096),
                max_stack INTEGER NOT NULL CHECK(max_stack BETWEEN 1 AND 2147483647),
                revision INTEGER NOT NULL
                    CHECK(revision BETWEEN 0 AND 9223372036854775807)
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_items (
                character_id TEXT NOT NULL,
                item_id TEXT NOT NULL
                    CHECK(length(item_id) BETWEEN 1 AND 64),
                quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 2147483647),
                PRIMARY KEY(character_id, item_id),
                FOREIGN KEY(character_id) REFERENCES inventory_snapshots(character_id)
                    ON DELETE CASCADE
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS inventory_mutations (
                request_id TEXT PRIMARY KEY
                    CHECK(length(request_id) BETWEEN 1 AND 128),
                character_id TEXT NOT NULL,
                expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_revision INTEGER NOT NULL CHECK(result_revision > 0),
                FOREIGN KEY(character_id) REFERENCES inventory_snapshots(character_id)
                    ON DELETE CASCADE
            )"""
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS inventory_mutations_character "
            "ON inventory_mutations(character_id, result_revision)"
        )
        self.db.commit()

    @staticmethod
    def _character_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise InventoryStoreError("invalid character identifier")
        return value

    @staticmethod
    def _request_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise InventoryStoreError("invalid request identifier")
        return value

    @staticmethod
    def _item_id(value):
        if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
            raise InventoryStoreError("invalid item identifier")
        return value

    @classmethod
    def _normalise_changes(cls, changes):
        if not isinstance(changes, (list, tuple)) or len(changes) > _MAX_BATCH:
            raise InventoryStoreError("changes must be a bounded sequence")
        totals = {}
        for entry in changes:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise InventoryStoreError("invalid inventory change")
            item_id = cls._item_id(entry[0])
            delta = entry[1]
            if type(delta) is not int or delta == 0 or abs(delta) > _MAX_STACK:
                raise InventoryStoreError("invalid inventory delta")
            totals[item_id] = totals.get(item_id, 0) + delta
        return tuple((item_id, delta) for item_id, delta in sorted(totals.items())
                     if delta != 0)

    @staticmethod
    def _snapshot(character_id, capacity, max_stack, revision, rows):
        return InventorySnapshot(
            character_id=character_id,
            capacity=int(capacity),
            max_stack=int(max_stack),
            revision=int(revision),
            items=tuple((str(item_id), int(quantity)) for item_id, quantity in rows),
        )

    @staticmethod
    def _decode_snapshot(raw):
        value = json.loads(raw)
        return InventorySnapshot(
            character_id=value["character_id"],
            capacity=int(value["capacity"]),
            max_stack=int(value["max_stack"]),
            revision=int(value["revision"]),
            items=tuple((str(item_id), int(quantity))
                        for item_id, quantity in value["items"]),
        )

    @staticmethod
    def _encode_snapshot(snapshot):
        return json.dumps(
            {
                "character_id": snapshot.character_id,
                "capacity": snapshot.capacity,
                "max_stack": snapshot.max_stack,
                "revision": snapshot.revision,
                "items": [list(item) for item in snapshot.items],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    def create(self, character_id: str, *, capacity: int = 20,
               max_stack: int = 99) -> InventorySnapshot:
        character_id = self._character_id(character_id)
        if type(capacity) is not int or not 1 <= capacity <= _MAX_CAPACITY:
            raise InventoryStoreError("invalid inventory capacity")
        if type(max_stack) is not int or not 1 <= max_stack <= _MAX_STACK:
            raise InventoryStoreError("invalid inventory stack limit")
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            try:
                self.db.execute(
                    "INSERT INTO inventory_snapshots "
                    "(character_id, capacity, max_stack, revision) VALUES (?, ?, ?, 0)",
                    (character_id, capacity, max_stack),
                )
            except sqlite3.IntegrityError as exc:
                raise InventoryAlreadyExists("inventory already exists") from exc
            self.db.commit()
            return InventorySnapshot(character_id, capacity, max_stack, 0, ())
        except BaseException:
            self.db.rollback()
            raise

    def get(self, character_id: str) -> InventorySnapshot:
        character_id = self._character_id(character_id)
        header = self.db.execute(
            "SELECT capacity, max_stack, revision FROM inventory_snapshots "
            "WHERE character_id=?", (character_id,)
        ).fetchone()
        if header is None:
            raise InventoryNotFound("inventory not found")
        rows = self.db.execute(
            "SELECT item_id, quantity FROM inventory_items "
            "WHERE character_id=? ORDER BY item_id", (character_id,)
        ).fetchall()
        return self._snapshot(character_id, *header, rows)

    def apply(self, character_id: str, request_id: str, expected_revision: int,
              changes) -> InventoryMutation:
        """Apply signed item deltas once and return the committed snapshot.

        Duplicate item IDs are aggregated before validation. An exact retry
        returns its original receipt even after later mutations. Reusing the
        request ID for a different character, revision or payload is rejected.
        """
        character_id = self._character_id(character_id)
        request_id = self._request_id(request_id)
        if (type(expected_revision) is not int
                or not 0 <= expected_revision < _MAX_REVISION):
            raise InventoryStoreError("invalid expected revision")
        normalised = self._normalise_changes(changes)
        if not normalised:
            raise InventoryStoreError("empty inventory mutation")
        payload_json = json.dumps(
            [list(change) for change in normalised],
            separators=(",", ":"), ensure_ascii=True,
        )
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                "SELECT character_id, expected_revision, payload_json, result_json "
                "FROM inventory_mutations WHERE request_id=?", (request_id,)
            ).fetchone()
            if previous is not None:
                if tuple(previous[:3]) != (
                    character_id, expected_revision, payload_json
                ):
                    raise InventoryOperationConflict(
                        "request id reused with different inventory mutation"
                    )
                snapshot = self._decode_snapshot(previous[3])
                self.db.commit()
                return InventoryMutation(snapshot, True)

            header = self.db.execute(
                "SELECT capacity, max_stack, revision FROM inventory_snapshots "
                "WHERE character_id=?", (character_id,)
            ).fetchone()
            if header is None:
                raise InventoryNotFound("inventory not found")
            capacity, max_stack, revision = map(int, header)
            if revision != expected_revision:
                raise InventoryRevisionConflict("stale inventory revision")
            if revision >= _MAX_REVISION:
                raise InventoryStoreError("inventory revision overflow")

            current_rows = self.db.execute(
                "SELECT item_id, quantity FROM inventory_items "
                "WHERE character_id=?", (character_id,)
            ).fetchall()
            candidate = {str(item_id): int(quantity)
                         for item_id, quantity in current_rows}
            for item_id, delta in normalised:
                updated = candidate.get(item_id, 0) + delta
                if not 0 <= updated <= max_stack:
                    raise InventoryStoreError(
                        "stack limit or insufficient inventory quantity"
                    )
                if updated == 0:
                    candidate.pop(item_id, None)
                else:
                    candidate[item_id] = updated
            if len(candidate) > capacity:
                raise InventoryStoreError("inventory capacity exceeded")

            for item_id, _ in normalised:
                quantity = candidate.get(item_id)
                if quantity is None:
                    self.db.execute(
                        "DELETE FROM inventory_items WHERE character_id=? AND item_id=?",
                        (character_id, item_id),
                    )
                else:
                    self.db.execute(
                        """INSERT INTO inventory_items(character_id, item_id, quantity)
                           VALUES (?, ?, ?)
                           ON CONFLICT(character_id, item_id)
                           DO UPDATE SET quantity=excluded.quantity""",
                        (character_id, item_id, quantity),
                    )

            updated_revision = revision + 1
            self.db.execute(
                "UPDATE inventory_snapshots SET revision=? WHERE character_id=? "
                "AND revision=?",
                (updated_revision, character_id, revision),
            )
            snapshot = self._snapshot(
                character_id, capacity, max_stack, updated_revision,
                sorted(candidate.items()),
            )
            result_json = self._encode_snapshot(snapshot)
            self.db.execute(
                """INSERT INTO inventory_mutations
                   (request_id, character_id, expected_revision, payload_json,
                    result_json, result_revision)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (request_id, character_id, expected_revision, payload_json,
                 result_json, updated_revision),
            )
            self.db.commit()
            return InventoryMutation(snapshot, False)
        except BaseException:
            self.db.rollback()
            raise
