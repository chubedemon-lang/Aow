"""Atomic synthetic quest-reward grants into authoritative inventory.

This is a local persistence primitive, not an AOW quest contract. The trusted
quest domain must validate completion before calling it. It records one award
per character/quest/item and updates inventory plus the award receipt in the
same caller-owned SQLite transaction.
"""
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass

from server.sqlite_inventory_store import (
    InventorySnapshot,
    InventoryStoreError,
    SqliteInventoryStore,
)


_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_ITEM_QUANTITY = 2**31 - 1
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_QUEST_INVENTORY_AWARD_COLUMNS = {
    "request_id": ("TEXT", 0, 1, None),
    "character_id": ("TEXT", 1, 0, None),
    "quest_id": ("INTEGER", 1, 0, None),
    "item_id": ("TEXT", 1, 0, None),
    "quantity": ("INTEGER", 1, 0, None),
    "expected_inventory_revision": ("INTEGER", 1, 0, None),
    "payload_json": ("TEXT", 1, 0, None),
    "result_json": ("TEXT", 1, 0, None),
    "result_revision": ("INTEGER", 1, 0, None),
}


class QuestInventoryAwardError(ValueError):
    """Invalid or inconsistent synthetic quest inventory award."""


class QuestInventoryAwardConflict(QuestInventoryAwardError):
    """A quest reward or idempotency key has already been used differently."""


@dataclass(frozen=True)
class QuestInventoryAward:
    snapshot: InventorySnapshot
    awarded: bool
    replayed: bool


class SqliteQuestInventoryAwardStore:
    """Persist an exactly-once quest item grant and its inventory mutation."""

    def __init__(self, connection: sqlite3.Connection,
                 inventory: SqliteInventoryStore):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        if not isinstance(inventory, SqliteInventoryStore) or inventory.db is not connection:
            raise ValueError("inventory store must use the same SQLite connection")

        self.db = connection
        self.inventory = inventory
        try:
            # Validate a pre-existing table before attempting dependent DDL.
            # A missing lookup index is allowed here because it is created
            # below and checked again before the transaction commits.
            self.db.execute("BEGIN IMMEDIATE")
            self._validate_schema(
                allow_missing=True, allow_missing_character_index=True
            )
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS quest_inventory_awards (
                    request_id TEXT PRIMARY KEY
                        CHECK(length(request_id) BETWEEN 1 AND 128),
                    character_id TEXT NOT NULL
                        CHECK(length(character_id) BETWEEN 1 AND 128),
                    quest_id INTEGER NOT NULL CHECK(quest_id BETWEEN 0 AND 9223372036854775807),
                    item_id TEXT NOT NULL CHECK(length(item_id) BETWEEN 1 AND 64),
                    quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 2147483647),
                    expected_inventory_revision INTEGER NOT NULL
                        CHECK(expected_inventory_revision BETWEEN 0 AND 9223372036854775806),
                    payload_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_revision INTEGER NOT NULL CHECK(result_revision > 0),
                    UNIQUE(character_id, quest_id, item_id)
                )"""
            )
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS quest_inventory_awards_character "
                "ON quest_inventory_awards(character_id, quest_id)"
            )
            self._validate_schema()
            self.db.commit()
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise

    def _validate_schema(self, *, allow_missing=False,
                         allow_missing_character_index=False):
        """Require the exact award table, uniqueness constraint and lookup index."""
        objects = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name=?",
            ("quest_inventory_awards",),
        ).fetchall()
        if not objects:
            if allow_missing:
                return False
            raise QuestInventoryAwardError("quest inventory award table is missing")
        if objects != [("table",)]:
            raise QuestInventoryAwardError("incompatible quest inventory award object")

        rows = self.db.execute(
            "PRAGMA table_info(quest_inventory_awards)"
        ).fetchall()
        actual_columns = {
            row[1]: (
                str(row[2]).strip().upper(), int(row[3]), int(row[5]), row[4]
            )
            for row in rows
        }
        if (len(rows) != len(_QUEST_INVENTORY_AWARD_COLUMNS)
                or actual_columns != _QUEST_INVENTORY_AWARD_COLUMNS):
            raise QuestInventoryAwardError("incompatible quest inventory award schema")

        if self.db.execute(
            "PRAGMA foreign_key_list(quest_inventory_awards)"
        ).fetchall():
            raise QuestInventoryAwardError(
                "unexpected quest inventory award foreign key"
            )

        indexes = self.db.execute(
            "PRAGMA index_list(quest_inventory_awards)"
        ).fetchall()

        def index_columns(index_name):
            quoted_name = index_name.replace('"', '""')
            return tuple(
                row[2] for row in self.db.execute(
                    'PRAGMA index_info("' + quoted_name + '")'
                ).fetchall()
            )

        primary_indexes = [
            row for row in indexes
            if len(row) >= 5 and int(row[2]) == 1
            and row[3] == "pk" and int(row[4]) == 0
        ]
        if (len(primary_indexes) != 1
                or index_columns(primary_indexes[0][1]) != ("request_id",)):
            raise QuestInventoryAwardError(
                "incompatible quest inventory award primary key"
            )

        unique_indexes = [
            row for row in indexes
            if len(row) >= 5 and int(row[2]) == 1
            and row[3] == "u" and int(row[4]) == 0
        ]
        if (len(unique_indexes) != 1
                or index_columns(unique_indexes[0][1])
                != ("character_id", "quest_id", "item_id")):
            raise QuestInventoryAwardError(
                "incompatible quest inventory award uniqueness constraint"
            )

        index_object = self.db.execute(
            "SELECT type, tbl_name FROM sqlite_master "
            "WHERE name='quest_inventory_awards_character'"
        ).fetchone()
        if index_object is None and allow_missing_character_index:
            return True
        if index_object != ("index", "quest_inventory_awards"):
            raise QuestInventoryAwardError(
                "incompatible quest inventory award character index"
            )
        character_indexes = [
            row for row in indexes
            if row[1] == "quest_inventory_awards_character"
        ]
        if (
            len(character_indexes) != 1
            or int(character_indexes[0][2]) != 0
            or character_indexes[0][3] != "c"
            or (len(character_indexes[0]) > 4
                and int(character_indexes[0][4]) != 0)
            or index_columns(character_indexes[0][1])
            != ("character_id", "quest_id")
        ):
            raise QuestInventoryAwardError(
                "incompatible quest inventory award character index"
            )
        return True

    @staticmethod
    def _request_id(value):
        if (type(value) is not str or not value
                or len(value) > 128 or value != value.strip()):
            raise QuestInventoryAwardError("invalid request identifier")
        return value

    @staticmethod
    def _item_id(value):
        if type(value) is not str or not _ID_PATTERN.fullmatch(value):
            raise QuestInventoryAwardError("invalid item identifier")
        return value

    @staticmethod
    def _decode_snapshot(raw, *, expected_character_id=None,
                         expected_revision=None):
        """Reuse the strict inventory receipt decoder at the quest boundary."""
        try:
            return SqliteInventoryStore._decode_snapshot(
                raw,
                expected_character_id=expected_character_id,
                expected_revision=expected_revision,
            )
        except InventoryStoreError as exc:
            raise QuestInventoryAwardError(
                "invalid quest inventory award receipt"
            ) from exc

    @staticmethod
    def _mutation_id(request_id):
        # Keep the inventory mutation receipt in a reserved, bounded namespace.
        digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        return "quest-" + digest

    def verify_integrity(self) -> dict:
        """Audit award receipts against their inventory mutations.

        The connection must be idle. The method owns one deferred read
        transaction and always rolls it back. The inventory store's own audit
        separately verifies the full inventory mutation history; this method
        proves that every quest award is linked to the exact reserved mutation
        and that no unpaired mutation remains in that reserved namespace.
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
        """Run the award audit while verify_integrity owns the read snapshot."""
        try:
            if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise QuestInventoryAwardError("SQLite quick_check failed")
            if self.db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise QuestInventoryAwardError(
                    "quest inventory award foreign key check failed"
                )

            duplicate_checks = (
                (
                    "SELECT 1 FROM quest_inventory_awards "
                    "GROUP BY request_id HAVING COUNT(*) > 1 LIMIT 1",
                    "duplicate quest inventory award request id",
                ),
                (
                    "SELECT 1 FROM quest_inventory_awards "
                    "GROUP BY character_id, quest_id, item_id "
                    "HAVING COUNT(*) > 1 LIMIT 1",
                    "duplicate quest inventory award identity",
                ),
            )
            for query, message in duplicate_checks:
                if self.db.execute(query).fetchone() is not None:
                    raise QuestInventoryAwardError(message)

            award_count = 0
            rows = self.db.execute(
                """SELECT request_id, character_id, quest_id, item_id, quantity,
                          expected_inventory_revision, payload_json, result_json,
                          result_revision
                   FROM quest_inventory_awards ORDER BY request_id"""
            )
            for (request_id, character_id, quest_id, item_id, quantity,
                 expected_revision, payload_json, result_json,
                 result_revision) in rows:
                request_id = self._request_id(request_id)
                character_id = SqliteInventoryStore._character_id(character_id)
                item_id = self._item_id(item_id)
                if (type(quest_id) is not int
                        or not 0 <= quest_id <= _MAX_SQLITE_INTEGER):
                    raise QuestInventoryAwardError(
                        "invalid stored quest inventory award identifier"
                    )
                if (type(quantity) is not int
                        or not 1 <= quantity <= _MAX_ITEM_QUANTITY):
                    raise QuestInventoryAwardError(
                        "invalid stored quest inventory award quantity"
                    )
                if (type(expected_revision) is not int
                        or not 0 <= expected_revision < _MAX_SQLITE_INTEGER
                        or type(result_revision) is not int
                        or result_revision != expected_revision + 1):
                    raise QuestInventoryAwardError(
                        "invalid stored quest inventory award revision"
                    )

                expected_payload = json.dumps(
                    [character_id, quest_id, item_id, quantity,
                     expected_revision],
                    separators=(",", ":"), ensure_ascii=True,
                )
                if type(payload_json) is not str or payload_json != expected_payload:
                    raise QuestInventoryAwardError(
                        "quest inventory award payload is not canonical"
                    )

                snapshot = self._decode_snapshot(
                    result_json,
                    expected_character_id=character_id,
                    expected_revision=result_revision,
                )
                if SqliteInventoryStore._encode_snapshot(snapshot) != result_json:
                    raise QuestInventoryAwardError(
                        "quest inventory award result is not canonical"
                    )

                mutation_payload = json.dumps(
                    [[item_id, quantity]],
                    separators=(",", ":"), ensure_ascii=True,
                )
                mutation = self.db.execute(
                    """SELECT character_id, expected_revision, payload_json,
                              result_json, result_revision
                       FROM inventory_mutations WHERE request_id=?""",
                    (self._mutation_id(request_id),),
                ).fetchone()
                if mutation is None or tuple(mutation) != (
                    character_id, expected_revision, mutation_payload,
                    result_json, result_revision,
                ):
                    raise QuestInventoryAwardError(
                        "quest inventory award does not match its inventory mutation"
                    )
                award_count += 1

            reserved_mutations = self.db.execute(
                """SELECT COUNT(*) FROM inventory_mutations
                   WHERE length(request_id)=70
                     AND substr(request_id, 1, 6)='quest-'
                     AND substr(request_id, 7) NOT GLOB '*[^0-9a-f]*'"""
            ).fetchone()[0]
            if type(reserved_mutations) is not int or reserved_mutations != award_count:
                raise QuestInventoryAwardError(
                    "unpaired reserved quest inventory mutation"
                )

            return {
                "awards": award_count,
                "linked_inventory_mutations": award_count,
            }
        except sqlite3.DatabaseError as exc:
            raise QuestInventoryAwardError(
                "quest inventory award integrity check could not complete"
            ) from exc

    def grant_once(self, character_id: str, request_id: str,
                   expected_inventory_revision: int, quest_id: int,
                   item_id: str, quantity: int) -> QuestInventoryAward:
        """Grant one item stack for a quest, or return the original receipt.

        The caller must have validated quest completion in trusted server code.
        Exact retries return the original inventory snapshot even if later
        inventory mutations have occurred. A second request for the same
        character/quest/item is rejected.
        """
        character_id = SqliteInventoryStore._character_id(character_id)
        request_id = self._request_id(request_id)
        item_id = self._item_id(item_id)
        if type(quest_id) is not int or not 0 <= quest_id <= _MAX_SQLITE_INTEGER:
            raise QuestInventoryAwardError("invalid quest identifier")
        if (type(expected_inventory_revision) is not int
                or not 0 <= expected_inventory_revision < _MAX_SQLITE_INTEGER):
            raise QuestInventoryAwardError("invalid inventory revision")
        if type(quantity) is not int or not 1 <= quantity <= _MAX_ITEM_QUANTITY:
            raise QuestInventoryAwardError("invalid item quantity")

        payload_json = json.dumps(
            [character_id, quest_id, item_id, quantity,
             expected_inventory_revision],
            separators=(",", ":"), ensure_ascii=True,
        )
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                """SELECT character_id, expected_inventory_revision,
                          payload_json, result_json, result_revision
                   FROM quest_inventory_awards WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:3]) != (
                    character_id, expected_inventory_revision, payload_json
                ):
                    raise QuestInventoryAwardConflict(
                        "request id reused with a different quest award"
                    )
                result_revision = previous[4]
                if (type(result_revision) is not int
                        or result_revision != expected_inventory_revision + 1):
                    raise QuestInventoryAwardError(
                        "invalid quest inventory award receipt revision"
                    )
                snapshot = self._decode_snapshot(
                    previous[3],
                    expected_character_id=character_id,
                    expected_revision=result_revision,
                )
                if owns_transaction:
                    self.db.commit()
                return QuestInventoryAward(snapshot, awarded=False, replayed=True)

            used = self.db.execute(
                """SELECT request_id FROM quest_inventory_awards
                   WHERE character_id=? AND quest_id=? AND item_id=?""",
                (character_id, quest_id, item_id),
            ).fetchone()
            if used is not None:
                raise QuestInventoryAwardConflict(
                    "quest item reward already granted"
                )

            mutation = self.inventory._apply_quest_award(
                character_id,
                self._mutation_id(request_id),
                expected_inventory_revision,
                [(item_id, quantity)],
            )
            if mutation.replayed:
                raise QuestInventoryAwardConflict(
                    "orphaned inventory receipt for quest award"
                )

            snapshot = mutation.snapshot
            result_json = self.inventory._encode_snapshot(snapshot)
            self.db.execute(
                """INSERT INTO quest_inventory_awards
                   (request_id, character_id, quest_id, item_id, quantity,
                    expected_inventory_revision, payload_json, result_json,
                    result_revision)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    request_id, character_id, quest_id, item_id, quantity,
                    expected_inventory_revision, payload_json, result_json,
                    snapshot.revision,
                ),
            )
            if owns_transaction:
                self.db.commit()
            return QuestInventoryAward(snapshot, awarded=True, replayed=False)
        except sqlite3.IntegrityError as exc:
            if owns_transaction:
                self.db.rollback()
            raise QuestInventoryAwardConflict(
                "quest reward receipt conflicts with an existing award"
            ) from exc
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            raise
