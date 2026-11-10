"""Atomic synthetic SQLite shop purchases across player and inventory state.

This is a server-domain persistence primitive only. Offer IDs, item IDs,
prices and purchase limits are caller-defined synthetic data, not AOW game
rules or an APK wire contract. The store requires the existing player-state
and inventory SQLite schemas and commits debit, grant, audit rows and receipt
in one BEGIN IMMEDIATE transaction.
"""
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass

from server.synthetic_player_state import PlayerSnapshot
from server.sqlite_inventory_store import InventorySnapshot
from server.sqlite_inventory_store import _MAX_REVISION as _MAX_INVENTORY_REVISION
from server.sqlite_player_state_store import _MAX_REVISION as _MAX_PLAYER_REVISION
from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_player_state_store import SqlitePlayerStateStore


_MAX_CURRENCY = 2**31 - 1
_MAX_STACK = 2**31 - 1
_MAX_PURCHASE_QUANTITY = 999
_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ShopStoreError(ValueError):
    """Invalid or inconsistent synthetic shop transaction."""


class ShopOfferNotFound(ShopStoreError):
    """The configured synthetic offer does not exist."""


class ShopPlayerNotFound(ShopStoreError):
    """No durable player snapshot exists for the character."""


class ShopInventoryNotFound(ShopStoreError):
    """No durable inventory exists for the character."""


class ShopInsufficientFunds(ShopStoreError):
    """The player does not have enough synthetic currency."""


class ShopRevisionConflict(ShopStoreError):
    """The caller supplied a stale player or inventory revision."""


class ShopOperationConflict(ShopStoreError):
    """An idempotency key was reused with a different purchase."""


@dataclass(frozen=True)
class ShopOffer:
    offer_id: str
    item_id: str
    unit_price: int

    def __post_init__(self):
        if not isinstance(self.offer_id, str) or not _ID_PATTERN.fullmatch(self.offer_id):
            raise ShopStoreError("invalid offer identifier")
        if not isinstance(self.item_id, str) or not _ID_PATTERN.fullmatch(self.item_id):
            raise ShopStoreError("invalid item identifier")
        if type(self.unit_price) is not int or not 1 <= self.unit_price <= _MAX_CURRENCY:
            raise ShopStoreError("invalid unit price")


@dataclass(frozen=True)
class ShopPurchase:
    character_id: str
    offer_id: str
    quantity: int
    total: int
    player: PlayerSnapshot
    inventory: InventorySnapshot
    replayed: bool


class SqliteShopStore:
    """Persist an atomic debit + inventory grant with idempotent receipts.

    The supplied connection must be idle at construction and before purchase.
    Constructing this store initializes the same schema used by
    SqlitePlayerStateStore and SqliteInventoryStore. A purchase updates those
    tables directly so the currency debit, item grant, their revision/audit
    records and the shop receipt cannot partially commit.
    """

    def __init__(self, connection: sqlite3.Connection,
                 offers: dict[str, ShopOffer], *,
                 max_purchase_quantity: int = 99):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        if (type(max_purchase_quantity) is not int
                or not 1 <= max_purchase_quantity <= _MAX_PURCHASE_QUANTITY):
            raise ShopStoreError("invalid maximum purchase quantity")
        if not isinstance(offers, dict) or any(
            not isinstance(offer, ShopOffer) or key != offer.offer_id
            for key, offer in offers.items()
        ):
            raise ShopStoreError("offer keys must match valid offer IDs")

        self.db = connection
        self.offers = dict(offers)
        self.max_purchase_quantity = max_purchase_quantity
        self.db.execute("PRAGMA busy_timeout = 10000")
        # Reuse the established schema and validation boundaries.
        SqlitePlayerStateStore(self.db)
        SqliteInventoryStore(self.db)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS shop_purchase_receipts (
                request_id TEXT PRIMARY KEY
                    CHECK(length(request_id) BETWEEN 1 AND 128),
                character_id TEXT NOT NULL
                    CHECK(length(character_id) BETWEEN 1 AND 128),
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                player_revision INTEGER NOT NULL CHECK(player_revision > 0),
                inventory_revision INTEGER NOT NULL CHECK(inventory_revision > 0)
            )"""
        )
        self.db.commit()

    @staticmethod
    def _character_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise ShopStoreError("invalid character identifier")
        return value

    @staticmethod
    def _request_id(value):
        if (not isinstance(value, str) or not value
                or len(value) > 128 or value != value.strip()):
            raise ShopStoreError("invalid request identifier")
        return value

    @staticmethod
    def _revision(value, label):
        if type(value) is not int or not 0 <= value < 2**63 - 1:
            raise ShopStoreError("invalid " + label)
        return value

    @staticmethod
    def _encode_result(purchase):
        return json.dumps(
            {
                "character_id": purchase.character_id,
                "offer_id": purchase.offer_id,
                "quantity": purchase.quantity,
                "total": purchase.total,
                "player": {
                    "level": purchase.player.level,
                    "experience": purchase.player.experience,
                    "currency": purchase.player.currency,
                    "revision": purchase.player.revision,
                },
                "inventory": {
                    "capacity": purchase.inventory.capacity,
                    "max_stack": purchase.inventory.max_stack,
                    "revision": purchase.inventory.revision,
                    "items": [list(item) for item in purchase.inventory.items],
                },
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    @staticmethod
    def _decode_result(raw, replayed):
        value = json.loads(raw)
        player = value["player"]
        inventory = value["inventory"]
        return ShopPurchase(
            character_id=value["character_id"],
            offer_id=value["offer_id"],
            quantity=int(value["quantity"]),
            total=int(value["total"]),
            player=PlayerSnapshot(
                value["character_id"], int(player["level"]),
                int(player["experience"]), int(player["currency"]),
                int(player["revision"]),
            ),
            inventory=InventorySnapshot(
                value["character_id"], int(inventory["capacity"]),
                int(inventory["max_stack"]), int(inventory["revision"]),
                tuple((str(item_id), int(quantity))
                      for item_id, quantity in inventory["items"]),
            ),
            replayed=replayed,
        )

    @staticmethod
    def _encode_inventory_snapshot(snapshot):
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

    @staticmethod
    def _mutation_id(request_id):
        # Reserve a bounded namespace in the existing player/inventory receipt
        # tables without exposing caller-controlled IDs to those namespaces.
        digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        return "shop-" + digest

    def purchase(self, character_id: str, request_id: str,
                 expected_player_revision: int,
                 expected_inventory_revision: int,
                 offer_id: str, quantity: int = 1) -> ShopPurchase:
        """Buy one configured offer atomically, or return its exact replay.

        Revisions are checked only for a new request. An exact retry returns
        the original committed snapshots even after subsequent mutations.
        """
        character_id = self._character_id(character_id)
        request_id = self._request_id(request_id)
        expected_player_revision = self._revision(
            expected_player_revision, "player revision"
        )
        expected_inventory_revision = self._revision(
            expected_inventory_revision, "inventory revision"
        )
        if type(quantity) is not int or not 1 <= quantity <= self.max_purchase_quantity:
            raise ShopStoreError("invalid purchase quantity")
        if not isinstance(offer_id, str) or not _ID_PATTERN.fullmatch(offer_id):
            raise ShopStoreError("invalid offer identifier")
        # The idempotency payload records caller intent, not mutable catalog
        # price data. A retry must replay the original receipt even if an offer
        # is later repriced or removed from the current catalog.
        payload_json = json.dumps(
            [
                character_id, expected_player_revision,
                expected_inventory_revision, offer_id, quantity,
            ],
            separators=(",", ":"), ensure_ascii=True,
        )
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                """SELECT character_id, payload_json, result_json
                   FROM shop_purchase_receipts WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:2]) != (character_id, payload_json):
                    raise ShopOperationConflict(
                        "request id reused with a different purchase"
                    )
                result = self._decode_result(previous[2], replayed=True)
                self.db.commit()
                return result

            offer = self.offers.get(offer_id)
            if offer is None:
                raise ShopOfferNotFound("unknown shop offer")
            total = offer.unit_price * quantity
            if total > _MAX_CURRENCY:
                raise ShopStoreError("purchase total exceeds currency limit")

            player_row = self.db.execute(
                """SELECT character_id, level, experience, currency, revision
                   FROM player_state_snapshots WHERE character_id=?""",
                (character_id,),
            ).fetchone()
            if player_row is None:
                raise ShopPlayerNotFound("player snapshot not found")
            player = PlayerSnapshot(
                player_row[0], int(player_row[1]), int(player_row[2]),
                int(player_row[3]), int(player_row[4]),
            )
            if player.revision != expected_player_revision:
                raise ShopRevisionConflict("stale player revision")

            inventory_header = self.db.execute(
                """SELECT capacity, max_stack, revision
                   FROM inventory_snapshots WHERE character_id=?""",
                (character_id,),
            ).fetchone()
            if inventory_header is None:
                raise ShopInventoryNotFound("inventory snapshot not found")
            capacity, max_stack, inventory_revision = map(int, inventory_header)
            if inventory_revision != expected_inventory_revision:
                raise ShopRevisionConflict("stale inventory revision")
            if (player.revision >= _MAX_PLAYER_REVISION
                    or inventory_revision >= _MAX_INVENTORY_REVISION):
                raise ShopStoreError("revision overflow")
            if player.currency < total:
                raise ShopInsufficientFunds("insufficient balance")

            rows = self.db.execute(
                """SELECT item_id, quantity FROM inventory_items
                   WHERE character_id=? ORDER BY item_id""",
                (character_id,),
            ).fetchall()
            candidate = {str(item_id): int(amount) for item_id, amount in rows}
            new_quantity = candidate.get(offer.item_id, 0) + quantity
            if new_quantity > min(max_stack, _MAX_STACK):
                raise ShopStoreError("inventory stack limit exceeded")
            if offer.item_id not in candidate and len(candidate) >= capacity:
                raise ShopStoreError("inventory capacity exceeded")
            candidate[offer.item_id] = new_quantity

            updated_player = PlayerSnapshot(
                character_id, player.level, player.experience,
                player.currency - total, player.revision + 1,
            )
            updated_inventory = InventorySnapshot(
                character_id, capacity, max_stack, inventory_revision + 1,
                tuple(sorted(candidate.items())),
            )

            player_update = self.db.execute(
                """UPDATE player_state_snapshots
                   SET currency=?, revision=?
                   WHERE character_id=? AND revision=?""",
                (updated_player.currency, updated_player.revision,
                 character_id, expected_player_revision),
            )
            if player_update.rowcount != 1:
                raise ShopRevisionConflict("player revision changed")

            self.db.execute(
                """INSERT INTO inventory_items(character_id, item_id, quantity)
                   VALUES (?, ?, ?)
                   ON CONFLICT(character_id, item_id)
                   DO UPDATE SET quantity=excluded.quantity""",
                (character_id, offer.item_id, new_quantity),
            )
            inventory_update = self.db.execute(
                """UPDATE inventory_snapshots SET revision=?
                   WHERE character_id=? AND revision=?""",
                (updated_inventory.revision, character_id,
                 expected_inventory_revision),
            )
            if inventory_update.rowcount != 1:
                raise ShopRevisionConflict("inventory revision changed")

            internal_request_id = self._mutation_id(request_id)
            inventory_payload = json.dumps(
                [[offer.item_id, quantity]],
                separators=(",", ":"), ensure_ascii=True,
            )
            self.db.execute(
                """INSERT INTO player_state_mutations
                   (request_id, character_id, expected_revision, requested_level,
                    experience_delta, currency_delta, result_level,
                    result_experience, result_currency, result_revision)
                   VALUES (?, ?, ?, NULL, 0, ?, ?, ?, ?, ?)""",
                (
                    internal_request_id, character_id, expected_player_revision,
                    -total, updated_player.level, updated_player.experience,
                    updated_player.currency, updated_player.revision,
                ),
            )
            self.db.execute(
                """INSERT INTO inventory_mutations
                   (request_id, character_id, expected_revision, payload_json,
                    result_json, result_revision)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    internal_request_id, character_id,
                    expected_inventory_revision, inventory_payload,
                    self._encode_inventory_snapshot(updated_inventory),
                    updated_inventory.revision,
                ),
            )
            result = ShopPurchase(
                character_id, offer.offer_id, quantity, total,
                updated_player, updated_inventory, False,
            )
            result_json = self._encode_result(result)
            self.db.execute(
                """INSERT INTO shop_purchase_receipts
                   (request_id, character_id, payload_json, result_json,
                    player_revision, inventory_revision)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    request_id, character_id, payload_json, result_json,
                    updated_player.revision, updated_inventory.revision,
                ),
            )
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise
