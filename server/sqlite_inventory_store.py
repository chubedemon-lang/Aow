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
_MAX_RECEIPT_JSON_BYTES = 512 * 1024
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_INVENTORY_SNAPSHOT_COLUMNS = {
    "character_id": ("TEXT", 0, 1, None),
    "capacity": ("INTEGER", 1, 0, None),
    "max_stack": ("INTEGER", 1, 0, None),
    "revision": ("INTEGER", 1, 0, None),
    "baseline_version": ("INTEGER", 1, 0, "0"),
}
_LEGACY_INVENTORY_SNAPSHOT_COLUMNS = {
    name: signature
    for name, signature in _INVENTORY_SNAPSHOT_COLUMNS.items()
    if name != "baseline_version"
}
_INVENTORY_CREATION_COLUMNS = {
    "character_id": ("TEXT", 0, 1, None),
    "baseline_json": ("TEXT", 1, 0, None),
}
_INVENTORY_ITEM_COLUMNS = {
    "character_id": ("TEXT", 1, 1, None),
    "item_id": ("TEXT", 1, 2, None),
    "quantity": ("INTEGER", 1, 0, None),
}
_INVENTORY_MUTATION_COLUMNS = {
    "request_id": ("TEXT", 0, 1, None),
    "character_id": ("TEXT", 1, 0, None),
    "expected_revision": ("INTEGER", 1, 0, None),
    "payload_json": ("TEXT", 1, 0, None),
    "result_json": ("TEXT", 1, 0, None),
    "result_revision": ("INTEGER", 1, 0, None),
}



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
    The supplied connection must be idle before construction. Mutations join an
    existing caller-owned transaction and never commit or roll it back.
    """

    def __init__(self, connection: sqlite3.Connection):
        if type(connection) is not sqlite3.Connection:
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute("PRAGMA foreign_keys = ON")
        try:
            # Schema creation, the legacy baseline migration and validation
            # form one unit. A rejected pre-existing schema must not leave
            # newly-created tables or a half-applied migration behind.
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS inventory_snapshots (
                    character_id TEXT PRIMARY KEY
                        CHECK(length(character_id) BETWEEN 1 AND 128),
                    capacity INTEGER NOT NULL CHECK(capacity BETWEEN 1 AND 4096),
                    max_stack INTEGER NOT NULL CHECK(max_stack BETWEEN 1 AND 2147483647),
                    revision INTEGER NOT NULL
                        CHECK(revision BETWEEN 0 AND 9223372036854775807),
                    baseline_version INTEGER NOT NULL DEFAULT 0
                        CHECK(baseline_version IN (0, 1))
                )"""
            )
            snapshot_object = self.db.execute(
                "SELECT type FROM sqlite_master WHERE name='inventory_snapshots'"
            ).fetchone()
            if snapshot_object != ("table",):
                raise InventoryStoreError("incompatible inventory snapshot table")
            snapshot_columns = {
                row[1] for row in self.db.execute(
                    "PRAGMA table_info(inventory_snapshots)"
                )
            }
            if "baseline_version" not in snapshot_columns:
                # Only the exact supported four-column legacy layout may be
                # migrated. Existing rows remain explicitly unanchored.
                self._validate_table_columns(
                    "inventory_snapshots",
                    _LEGACY_INVENTORY_SNAPSHOT_COLUMNS,
                )
                self.db.execute(
                    "ALTER TABLE inventory_snapshots ADD COLUMN "
                    "baseline_version INTEGER NOT NULL DEFAULT 0 "
                    "CHECK(baseline_version IN (0, 1))"
                )
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS inventory_creations (
                    character_id TEXT PRIMARY KEY
                        CHECK(length(character_id) BETWEEN 1 AND 128),
                    baseline_json TEXT NOT NULL,
                    FOREIGN KEY(character_id) REFERENCES inventory_snapshots(character_id)
                        ON DELETE CASCADE
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
            self._validate_schema()
            self.db.commit()
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise

    def _validate_table_columns(self, table_name, expected_columns):
        """Require an exact persisted column signature for a known table."""
        if type(table_name) is not str or table_name not in {
            "inventory_snapshots",
            "inventory_creations",
            "inventory_items",
            "inventory_mutations",
        }:
            raise InventoryStoreError("invalid inventory table selector")
        table = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name=?", (table_name,)
        ).fetchone()
        if table != ("table",):
            raise InventoryStoreError("incompatible inventory table")
        rows = self.db.execute(
            "PRAGMA table_info(" + table_name + ")"
        ).fetchall()
        actual_columns = {
            row[1]: (
                str(row[2]).strip().upper(),
                int(row[3]),
                int(row[5]),
                row[4],
            )
            for row in rows
        }
        if (len(rows) != len(expected_columns)
                or actual_columns != expected_columns):
            raise InventoryStoreError("incompatible inventory schema")

    def _validate_foreign_key(self, table_name, *, allow_legacy_missing=False):
        """Validate a character ownership FK, tolerating its absence in legacy tables."""
        rows = self.db.execute(
            "PRAGMA foreign_key_list(" + table_name + ")"
        ).fetchall()
        actual = tuple(
            (row[2], row[3], row[4], row[5], row[6], row[7])
            for row in rows
        )
        expected = ((
            "inventory_snapshots", "character_id", "character_id",
            "NO ACTION", "CASCADE", "NONE",
        ),)
        if not actual and allow_legacy_missing:
            return
        if actual != expected:
            raise InventoryStoreError("incompatible inventory ownership foreign key")

    def _validate_schema(self):
        """Validate persisted inventory tables, ownership links and mutation index."""
        self._validate_table_columns(
            "inventory_snapshots", _INVENTORY_SNAPSHOT_COLUMNS
        )
        self._validate_table_columns(
            "inventory_creations", _INVENTORY_CREATION_COLUMNS
        )
        self._validate_table_columns(
            "inventory_items", _INVENTORY_ITEM_COLUMNS
        )
        self._validate_table_columns(
            "inventory_mutations", _INVENTORY_MUTATION_COLUMNS
        )
        self._validate_foreign_key("inventory_creations")
        # Older supported databases predate these two foreign keys. If one is
        # present it must be the exact cascade relationship; a malformed FK
        # is never accepted.
        self._validate_foreign_key(
            "inventory_items", allow_legacy_missing=True
        )
        self._validate_foreign_key(
            "inventory_mutations", allow_legacy_missing=True
        )

        index_object = self.db.execute(
            "SELECT type, tbl_name FROM sqlite_master "
            "WHERE name='inventory_mutations_character'"
        ).fetchone()
        if index_object != ("index", "inventory_mutations"):
            raise InventoryStoreError("incompatible inventory mutation index")
        indexes = [
            row for row in self.db.execute(
                "PRAGMA index_list(inventory_mutations)"
            ).fetchall()
            if row[1] == "inventory_mutations_character"
        ]
        if (
            len(indexes) != 1
            or int(indexes[0][2]) != 0
            or indexes[0][3] != "c"
            or (len(indexes[0]) > 4 and int(indexes[0][4]) != 0)
        ):
            raise InventoryStoreError("incompatible inventory mutation index")
        indexed_columns = tuple(
            row[2] for row in self.db.execute(
                "PRAGMA index_info(inventory_mutations_character)"
            ).fetchall()
        )
        if indexed_columns != ("character_id", "result_revision"):
            raise InventoryStoreError("incompatible inventory mutation index")

    @staticmethod
    def _character_id(value):
        if (type(value) is not str or not value
                or len(value) > 128 or value != value.strip()):
            raise InventoryStoreError("invalid character identifier")
        return value

    @staticmethod
    def _request_id(value):
        if (type(value) is not str or not value
                or len(value) > 128 or value != value.strip()):
            raise InventoryStoreError("invalid request identifier")
        return value

    @staticmethod
    def _item_id(value):
        if type(value) is not str or not _ID_PATTERN.fullmatch(value):
            raise InventoryStoreError("invalid item identifier")
        return value

    @classmethod
    def _normalise_changes(cls, changes):
        if type(changes) not in (list, tuple) or len(changes) > _MAX_BATCH:
            raise InventoryStoreError("changes must be a bounded sequence")
        totals = {}
        for entry in changes:
            if type(entry) not in (list, tuple) or len(entry) != 2:
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
        """Decode a persisted/current snapshot without coercing SQLite values."""
        character_id = SqliteInventoryStore._character_id(character_id)
        if (type(capacity) is not int or not 1 <= capacity <= _MAX_CAPACITY
                or type(max_stack) is not int
                or not 1 <= max_stack <= _MAX_STACK
                or type(revision) is not int
                or not 0 <= revision <= _MAX_REVISION):
            raise InventoryStoreError("invalid stored inventory snapshot")
        if type(rows) not in (list, tuple) or len(rows) > capacity:
            raise InventoryStoreError("invalid stored inventory items")

        items = []
        previous_id = None
        for row in rows:
            if type(row) not in (list, tuple) or len(row) != 2:
                raise InventoryStoreError("invalid stored inventory item")
            item_id = SqliteInventoryStore._item_id(row[0])
            quantity = row[1]
            if (type(quantity) is not int or not 1 <= quantity <= max_stack
                    or (previous_id is not None and item_id <= previous_id)):
                raise InventoryStoreError("invalid stored inventory item")
            items.append((item_id, quantity))
            previous_id = item_id

        return InventorySnapshot(
            character_id=character_id,
            capacity=capacity,
            max_stack=max_stack,
            revision=revision,
            items=tuple(items),
        )

    @staticmethod
    def _decode_snapshot(raw, *, expected_character_id=None,
                         expected_revision=None):
        """Decode and validate a durable idempotency receipt before replay.

        SQLite receipt rows are durable state, not trusted merely because this
        process originally wrote them. Reject ambiguous JSON and values that
        Python would otherwise coerce (notably bool to int or numbers to str).
        """
        def reject_constant(_value):
            raise InventoryStoreError(
                "non-finite JSON value in inventory receipt snapshot"
            )

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise InventoryStoreError(
                        "duplicate JSON key in inventory receipt snapshot"
                    )
                result[key] = value
            return result

        if (type(raw) is not str or len(raw) > _MAX_RECEIPT_JSON_BYTES
                or not raw.isascii()):
            raise InventoryStoreError("invalid inventory receipt snapshot JSON")
        try:
            value = json.loads(
                raw,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except InventoryStoreError:
            raise
        except (TypeError, ValueError, RecursionError) as exc:
            raise InventoryStoreError(
                "invalid inventory receipt snapshot JSON"
            ) from exc

        expected_keys = {
            "character_id", "capacity", "max_stack", "revision", "items"
        }
        if type(value) is not dict or set(value) != expected_keys:
            raise InventoryStoreError("invalid inventory receipt snapshot")

        character_id = SqliteInventoryStore._character_id(value["character_id"])
        capacity = value["capacity"]
        max_stack = value["max_stack"]
        revision = value["revision"]
        items = value["items"]
        if (type(capacity) is not int or not 1 <= capacity <= _MAX_CAPACITY
                or type(max_stack) is not int
                or not 1 <= max_stack <= _MAX_STACK
                or type(revision) is not int
                or not 0 <= revision <= _MAX_REVISION
                or type(items) is not list or len(items) > capacity):
            raise InventoryStoreError("invalid inventory receipt snapshot")
        if (expected_character_id is not None
                and character_id != expected_character_id):
            raise InventoryStoreError("inventory receipt character mismatch")
        if (expected_revision is not None
                and (type(expected_revision) is not int
                     or revision != expected_revision)):
            raise InventoryStoreError("inventory receipt revision mismatch")

        decoded = []
        previous_id = None
        for pair in items:
            if type(pair) is not list or len(pair) != 2:
                raise InventoryStoreError("invalid inventory receipt item")
            item_id = SqliteInventoryStore._item_id(pair[0])
            quantity = pair[1]
            if (type(quantity) is not int or not 1 <= quantity <= max_stack
                    or (previous_id is not None and item_id <= previous_id)):
                raise InventoryStoreError("invalid inventory receipt item")
            decoded.append((item_id, quantity))
            previous_id = item_id

        return InventorySnapshot(
            character_id, capacity, max_stack, revision, tuple(decoded)
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

    def verify_integrity(self) -> dict:
        """Audit inventory state under one consistent, read-only snapshot.

        The connection must be idle. This method owns a deferred read
        transaction and always rolls it back, including on validation failure.
        """
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN")
        try:
            return self._verify_integrity_snapshot()
        finally:
            if self.db.in_transaction:
                self.db.rollback()

    def _verify_integrity_snapshot(self) -> dict:
        """Run the audit while verify_integrity owns the read snapshot."""
        if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise InventoryStoreError("SQLite quick_check failed")
        if self.db.execute("PRAGMA foreign_key_check").fetchall():
            raise InventoryStoreError("inventory foreign key check failed")

        tables = {
            row[0] for row in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        snapshot_columns = {
            row[1] for row in self.db.execute(
                "PRAGMA table_info(inventory_snapshots)"
            )
        }
        has_baseline_version = "baseline_version" in snapshot_columns
        has_creation_table = "inventory_creations" in tables
        if has_baseline_version != has_creation_table:
            raise InventoryStoreError("inventory creation schema is incomplete")
        if has_creation_table:
            creation_columns = {
                row[1] for row in self.db.execute(
                    "PRAGMA table_info(inventory_creations)"
                )
            }
            if not {"character_id", "baseline_json"}.issubset(creation_columns):
                raise InventoryStoreError("inventory creation schema is incomplete")

        def reject_constant(_value):
            raise InventoryStoreError(
                "non-finite JSON value in inventory mutation payload"
            )

        def decode_receipt_snapshot(raw):
            # Reuse the strict replay decoder so integrity audits apply the same
            # duplicate-key, type, nesting, and size checks as idempotent replay.
            return self._decode_snapshot(raw)

        snapshots = {}
        baseline_versions = {}
        item_rows = {}
        for character_id, item_id, quantity in self.db.execute(
            """SELECT character_id, item_id, quantity
               FROM inventory_items ORDER BY character_id, item_id"""
        ):
            character_id = self._character_id(character_id)
            item_id = self._item_id(item_id)
            if type(quantity) is not int or quantity <= 0:
                raise InventoryStoreError("invalid stored inventory quantity")
            current = item_rows.setdefault(character_id, [])
            current.append((item_id, quantity))

        baseline_column = ", baseline_version" if has_baseline_version else ""
        snapshot_rows = self.db.execute(
            "SELECT character_id, capacity, max_stack, revision"
            + baseline_column
            + " FROM inventory_snapshots ORDER BY character_id"
        )
        for row in snapshot_rows:
            character_id, capacity, max_stack, revision = row[:4]
            character_id = self._character_id(character_id)
            baseline_version = row[4] if has_baseline_version else 0
            if character_id in snapshots:
                raise InventoryStoreError("duplicate inventory snapshot")
            if (type(capacity) is not int or not 1 <= capacity <= _MAX_CAPACITY
                    or type(max_stack) is not int
                    or not 1 <= max_stack <= _MAX_STACK
                    or type(revision) is not int
                    or not 0 <= revision <= _MAX_REVISION
                    or type(baseline_version) is not int
                    or baseline_version not in (0, 1)):
                raise InventoryStoreError("invalid stored inventory snapshot")
            items = item_rows.pop(character_id, [])
            if (len(items) > capacity
                    or any(quantity > max_stack for _, quantity in items)):
                raise InventoryStoreError(
                    "stored inventory exceeds capacity or stack limit"
                )
            snapshots[character_id] = InventorySnapshot(
                character_id, capacity, max_stack, revision, tuple(items)
            )
            baseline_versions[character_id] = baseline_version
        if item_rows:
            raise InventoryStoreError("inventory item has no snapshot")

        baselines = {}
        if has_creation_table:
            creation_rows = self.db.execute(
                """SELECT character_id, baseline_json
                   FROM inventory_creations ORDER BY character_id"""
            )
        else:
            creation_rows = ()
        for character_id, baseline_json in creation_rows:
            character_id = self._character_id(character_id)
            if character_id in baselines:
                raise InventoryStoreError("duplicate inventory creation receipt")
            stored = snapshots.get(character_id)
            if stored is None:
                raise InventoryStoreError("creation receipt has no inventory snapshot")
            if baseline_versions[character_id] != 1:
                raise InventoryStoreError("creation receipt baseline marker mismatch")
            baseline = decode_receipt_snapshot(
                baseline_json,
            )
            if (baseline_json != self._encode_snapshot(baseline)
                    or baseline.character_id != character_id
                    or baseline.revision != 0
                    or baseline.capacity != stored.capacity
                    or baseline.max_stack != stored.max_stack
                    or baseline.items != ()):
                raise InventoryStoreError("invalid inventory creation baseline")
            baselines[character_id] = baseline

        for character_id, baseline_version in baseline_versions.items():
            if baseline_version == 1 and character_id not in baselines:
                raise InventoryStoreError("inventory creation receipt is missing")
            if baseline_version == 0 and character_id in baselines:
                raise InventoryStoreError("creation receipt baseline marker mismatch")

        replayed = dict(baselines)
        mutation_rows = self.db.execute(
            """SELECT request_id, character_id, expected_revision,
                      payload_json, result_json, result_revision
               FROM inventory_mutations
               ORDER BY character_id, result_revision, request_id"""
        )
        mutation_count = 0

        for (request_id, character_id, expected_revision, payload_json,
             result_json, result_revision) in mutation_rows:
            self._request_id(request_id)
            character_id = self._character_id(character_id)
            stored = snapshots.get(character_id)
            if stored is None:
                raise InventoryStoreError("mutation has no inventory snapshot")
            if (type(expected_revision) is not int
                    or not 0 <= expected_revision < _MAX_REVISION
                    or type(result_revision) is not int
                    or result_revision != expected_revision + 1):
                raise InventoryStoreError("invalid inventory mutation revision")

            if (type(payload_json) is not str
                    or len(payload_json) > _MAX_RECEIPT_JSON_BYTES
                    or not payload_json.isascii()):
                raise InventoryStoreError("invalid inventory mutation payload")
            try:
                payload = json.loads(payload_json, parse_constant=reject_constant)
                normalised = self._normalise_changes(payload)
            except (TypeError, ValueError, RecursionError) as exc:
                raise InventoryStoreError(
                    "invalid inventory mutation payload"
                ) from exc
            if not normalised or payload != [list(change) for change in normalised]:
                raise InventoryStoreError("non-canonical inventory mutation payload")

            recorded = decode_receipt_snapshot(result_json)
            if (recorded.character_id != character_id
                    or recorded.revision != result_revision
                    or recorded.capacity != stored.capacity
                    or recorded.max_stack != stored.max_stack):
                raise InventoryStoreError(
                    "inventory receipt identity or revision mismatch"
                )

            current = replayed.get(character_id)
            if current is None:
                if expected_revision != 0:
                    raise InventoryStoreError("inventory mutation history has a gap")
                if character_id in baselines:
                    current = baselines[character_id]
                else:
                    # Legacy schema/rows have no independent creation receipt.
                    # Preserve their historical inverse-delta validation, but
                    # report them as unanchored rather than claiming a baseline.
                    baseline = dict(recorded.items)
                    for item_id, delta in normalised:
                        previous = baseline.get(item_id, 0) - delta
                        if not 0 <= previous <= recorded.max_stack:
                            raise InventoryStoreError(
                                "invalid first inventory mutation baseline"
                            )
                        if previous:
                            baseline[item_id] = previous
                        else:
                            baseline.pop(item_id, None)
                    if len(baseline) > recorded.capacity:
                        raise InventoryStoreError(
                            "first inventory baseline exceeds capacity"
                        )
                    current = InventorySnapshot(
                        character_id, recorded.capacity, recorded.max_stack, 0,
                        tuple(sorted(baseline.items())),
                    )

            if current.revision != expected_revision:
                raise InventoryStoreError("inventory mutation history has a gap")
            candidate = dict(current.items)
            for item_id, delta in normalised:
                updated = candidate.get(item_id, 0) + delta
                if not 0 <= updated <= current.max_stack:
                    raise InventoryStoreError(
                        "inventory mutation history exceeds stack limits"
                    )
                if updated:
                    candidate[item_id] = updated
                else:
                    candidate.pop(item_id, None)
            if len(candidate) > current.capacity:
                raise InventoryStoreError(
                    "inventory mutation history exceeds capacity"
                )
            expected = InventorySnapshot(
                character_id, current.capacity, current.max_stack,
                result_revision, tuple(sorted(candidate.items())),
            )
            if recorded != expected:
                raise InventoryStoreError(
                    "inventory receipt does not match mutation history"
                )

            replayed[character_id] = recorded
            mutation_count += 1

        for character_id, snapshot in snapshots.items():
            historical = replayed.get(character_id)
            if historical is None:
                if snapshot.revision != 0 or snapshot.items:
                    raise InventoryStoreError(
                        "inventory snapshot has no creation or mutation history"
                    )
            elif historical != snapshot:
                raise InventoryStoreError(
                    "current inventory snapshot does not match mutation history"
                )

        anchored_count = len(baselines)
        return {
            "snapshots": len(snapshots),
            "items": sum(len(snapshot.items) for snapshot in snapshots.values()),
            "mutations": mutation_count,
            "anchored_snapshots": anchored_count,
            "legacy_unanchored_snapshots": len(snapshots) - anchored_count,
        }

    def create(self, character_id: str, *, capacity: int = 20,
               max_stack: int = 99) -> InventorySnapshot:
        character_id = self._character_id(character_id)
        if type(capacity) is not int or not 1 <= capacity <= _MAX_CAPACITY:
            raise InventoryStoreError("invalid inventory capacity")
        if type(max_stack) is not int or not 1 <= max_stack <= _MAX_STACK:
            raise InventoryStoreError("invalid inventory stack limit")
        snapshot = InventorySnapshot(character_id, capacity, max_stack, 0, ())
        owns_transaction = not self.db.in_transaction
        savepoint_name = "inventory_create"
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        else:
            self.db.execute("SAVEPOINT " + savepoint_name)
        try:
            try:
                self.db.execute(
                    "INSERT INTO inventory_snapshots "
                    "(character_id, capacity, max_stack, revision, baseline_version) "
                    "VALUES (?, ?, ?, 0, 1)",
                    (character_id, capacity, max_stack),
                )
            except sqlite3.IntegrityError as exc:
                raise InventoryAlreadyExists("inventory already exists") from exc
            self.db.execute(
                "INSERT INTO inventory_creations (character_id, baseline_json) "
                "VALUES (?, ?)",
                (character_id, self._encode_snapshot(snapshot)),
            )
            if owns_transaction:
                self.db.commit()
            else:
                self.db.execute("RELEASE SAVEPOINT " + savepoint_name)
            return snapshot
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            else:
                self.db.execute("ROLLBACK TO SAVEPOINT " + savepoint_name)
                self.db.execute("RELEASE SAVEPOINT " + savepoint_name)
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
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                "SELECT character_id, expected_revision, payload_json, result_json, "
                "result_revision FROM inventory_mutations WHERE request_id=?",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:3]) != (
                    character_id, expected_revision, payload_json
                ):
                    raise InventoryOperationConflict(
                        "request id reused with different inventory mutation"
                    )
                result_revision = previous[4]
                if (type(result_revision) is not int
                        or result_revision != expected_revision + 1):
                    raise InventoryStoreError("invalid inventory receipt revision")
                snapshot = self._decode_snapshot(
                    previous[3],
                    expected_character_id=character_id,
                    expected_revision=result_revision,
                )
                if owns_transaction:
                    self.db.commit()
                return InventoryMutation(snapshot, True)

            header = self.db.execute(
                "SELECT capacity, max_stack, revision FROM inventory_snapshots "
                "WHERE character_id=?", (character_id,)
            ).fetchone()
            if header is None:
                raise InventoryNotFound("inventory not found")
            current_rows = self.db.execute(
                "SELECT item_id, quantity FROM inventory_items "
                "WHERE character_id=? ORDER BY item_id", (character_id,)
            ).fetchall()
            current_snapshot = self._snapshot(
                character_id, *header, current_rows
            )
            capacity = current_snapshot.capacity
            max_stack = current_snapshot.max_stack
            revision = current_snapshot.revision
            if revision != expected_revision:
                raise InventoryRevisionConflict("stale inventory revision")
            if revision >= _MAX_REVISION:
                raise InventoryStoreError("inventory revision overflow")

            candidate = dict(current_snapshot.items)
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
            if owns_transaction:
                self.db.commit()
            return InventoryMutation(snapshot, False)
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            raise
