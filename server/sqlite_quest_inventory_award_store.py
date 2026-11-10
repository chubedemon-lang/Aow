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

from server.sqlite_inventory_store import InventorySnapshot, SqliteInventoryStore


_MAX_SQLITE_INTEGER = 2**63 - 1
_MAX_ITEM_QUANTITY = 2**31 - 1
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


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
        self.db.commit()

    @staticmethod
    def _request_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise QuestInventoryAwardError("invalid request identifier")
        return value

    @staticmethod
    def _item_id(value):
        if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
            raise QuestInventoryAwardError("invalid item identifier")
        return value

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
    def _mutation_id(request_id):
        # Keep the inventory mutation receipt in a reserved, bounded namespace.
        digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        return "quest-" + digest

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
                """SELECT payload_json, result_json
                   FROM quest_inventory_awards WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if previous[0] != payload_json:
                    raise QuestInventoryAwardConflict(
                        "request id reused with a different quest award"
                    )
                snapshot = self._decode_snapshot(previous[1])
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

            mutation = self.inventory.apply(
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
