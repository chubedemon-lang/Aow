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
from server.sqlite_inventory_store import InventorySnapshot, InventoryStoreError
from server.sqlite_inventory_store import _MAX_REVISION as _MAX_INVENTORY_REVISION
from server.sqlite_player_state_store import (
    PlayerStoreError,
    _MAX_REVISION as _MAX_PLAYER_REVISION,
    SqlitePlayerStateStore,
)
from server.sqlite_inventory_store import SqliteInventoryStore


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

    The supplied connection must be idle at construction. Purchases start their own
    transaction when called standalone, or join an existing caller-owned
    transaction without committing or rolling it back.
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
    def _decode_result(raw, replayed, *, expected_character_id,
                       expected_offer_id, expected_quantity,
                       expected_player_revision, expected_inventory_revision):
        """Decode a durable purchase receipt without coercing untrusted values."""
        def reject_constant(_value):
            raise ShopStoreError("non-finite value in shop receipt")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ShopStoreError("duplicate JSON key in shop receipt")
                result[key] = value
            return result

        if type(raw) is not str or len(raw) > 512 * 1024:
            raise ShopStoreError("invalid shop receipt JSON")
        try:
            value = json.loads(
                raw,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except ShopStoreError:
            raise
        except (TypeError, ValueError, RecursionError) as exc:
            raise ShopStoreError("invalid shop receipt JSON") from exc

        if (type(value) is not dict
                or set(value) != {
                    "character_id", "offer_id", "quantity", "total",
                    "player", "inventory",
                }):
            raise ShopStoreError("invalid shop receipt shape")
        character_id = SqliteShopStore._character_id(value["character_id"])
        offer_id = value["offer_id"]
        quantity = value["quantity"]
        total = value["total"]
        if (character_id != expected_character_id
                or not isinstance(offer_id, str)
                or not _ID_PATTERN.fullmatch(offer_id)
                or offer_id != expected_offer_id
                or type(quantity) is not int
                or quantity != expected_quantity
                or not 1 <= quantity <= _MAX_PURCHASE_QUANTITY
                or type(total) is not int
                or not 1 <= total <= _MAX_CURRENCY):
            raise ShopStoreError("shop receipt identity or amount mismatch")

        player = value["player"]
        if (type(player) is not dict
                or set(player) != {"level", "experience", "currency", "revision"}):
            raise ShopStoreError("invalid shop player receipt")
        level = player["level"]
        experience = player["experience"]
        currency = player["currency"]
        player_revision = player["revision"]
        if (type(level) is not int or not 1 <= level <= 1000
                or type(experience) is not int
                or not 0 <= experience <= 2**63 - 1
                or type(currency) is not int
                or not 0 <= currency <= _MAX_CURRENCY
                or type(player_revision) is not int
                or player_revision != expected_player_revision):
            raise ShopStoreError("invalid shop player receipt values")

        inventory = value["inventory"]
        try:
            if type(inventory) is not dict:
                raise ShopStoreError("invalid shop inventory receipt shape")
            inventory_value = dict(inventory)
            nested_character_id = inventory_value.get("character_id", character_id)
            if nested_character_id != character_id:
                raise ShopStoreError("shop inventory receipt character mismatch")
            # Shop receipts historically keep character_id at the root rather
            # than inside the nested inventory object. Supply that already
            # validated identity to the shared strict inventory decoder.
            inventory_value["character_id"] = character_id
            inventory_json = json.dumps(
                inventory_value, separators=(",", ":"), ensure_ascii=True
            )
            inventory_snapshot = SqliteInventoryStore._decode_snapshot(
                inventory_json,
                expected_character_id=character_id,
                expected_revision=expected_inventory_revision,
            )
        except ShopStoreError:
            raise
        except (InventoryStoreError, TypeError, ValueError) as exc:
            raise ShopStoreError("invalid shop inventory receipt") from exc

        return ShopPurchase(
            character_id=character_id,
            offer_id=offer_id,
            quantity=quantity,
            total=total,
            player=PlayerSnapshot(
                character_id, level, experience, currency, player_revision
            ),
            inventory=inventory_snapshot,
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


    def verify_integrity(self) -> dict:
        """Audit purchase receipts against their paired player/inventory mutations.

        The connection must be idle. The method owns a deferred read transaction
        and always rolls it back. The independent player and inventory audits
        reconstruct their complete mutation histories; this method links each
        shop receipt to the exact reserved mutation in both histories.
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
        """Run the shop receipt audit inside verify_integrity's read snapshot."""
        try:
            if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ShopStoreError("SQLite quick_check failed")
            if self.db.execute("PRAGMA foreign_key_check").fetchall():
                raise ShopStoreError("shop foreign key check failed")

            tables = {
                row[0] for row in self.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            required = {
                "shop_purchase_receipts",
                "player_state_snapshots",
                "player_state_mutations",
                "inventory_snapshots",
                "inventory_items",
                "inventory_mutations",
            }
            if not required.issubset(tables):
                raise ShopStoreError("shop integrity schema is incomplete")

            def reject_constant(_value):
                raise ValueError("non-finite JSON constant")

            purchase_count = 0
            seen_mutations = set()
            rows = self.db.execute(
                """SELECT request_id, character_id, payload_json, result_json,
                          player_revision, inventory_revision
                   FROM shop_purchase_receipts ORDER BY request_id"""
            )
            for (request_id, character_id, payload_json, result_json,
                 player_revision, inventory_revision) in rows:
                request_id = self._request_id(request_id)
                character_id = self._character_id(character_id)
                if (type(payload_json) is not str
                        or len(payload_json) > 4096
                        or not payload_json.isascii()):
                    raise ShopStoreError("invalid shop purchase payload")

                try:
                    payload = json.loads(
                        payload_json, parse_constant=reject_constant
                    )
                except (TypeError, ValueError, RecursionError) as exc:
                    raise ShopStoreError(
                        "invalid shop purchase payload"
                    ) from exc
                if (type(payload) is not list or len(payload) != 5
                        or payload[0] != character_id
                        or type(payload[1]) is not int
                        or not 0 <= payload[1] < _MAX_PLAYER_REVISION
                        or type(payload[2]) is not int
                        or not 0 <= payload[2] < _MAX_INVENTORY_REVISION
                        or type(payload[3]) is not str
                        or not _ID_PATTERN.fullmatch(payload[3])
                        or type(payload[4]) is not int
                        or not 1 <= payload[4] <= _MAX_PURCHASE_QUANTITY):
                    raise ShopStoreError("invalid shop purchase payload fields")
                if json.dumps(
                    payload, separators=(",", ":"), ensure_ascii=True
                ) != payload_json:
                    raise ShopStoreError("shop purchase payload is not canonical")

                expected_player_revision = payload[1]
                expected_inventory_revision = payload[2]
                offer_id = payload[3]
                quantity = payload[4]
                if (type(player_revision) is not int
                        or player_revision != expected_player_revision + 1
                        or type(inventory_revision) is not int
                        or inventory_revision != expected_inventory_revision + 1):
                    raise ShopStoreError("invalid shop purchase revision columns")

                purchase = self._decode_result(
                    result_json,
                    replayed=True,
                    expected_character_id=character_id,
                    expected_offer_id=offer_id,
                    expected_quantity=quantity,
                    expected_player_revision=player_revision,
                    expected_inventory_revision=inventory_revision,
                )
                if (purchase.total % quantity != 0
                        or self._encode_result(purchase) != result_json):
                    raise ShopStoreError("shop purchase result is not canonical")

                internal_request_id = self._mutation_id(request_id)
                if internal_request_id in seen_mutations:
                    raise ShopStoreError("duplicate shop mutation identity")
                seen_mutations.add(internal_request_id)

                player_mutation = self.db.execute(
                    """SELECT character_id, expected_revision, requested_level,
                              experience_delta, currency_delta, result_level,
                              result_experience, result_currency, result_revision
                       FROM player_state_mutations WHERE request_id=?""",
                    (internal_request_id,),
                ).fetchone()
                expected_player_mutation = (
                    character_id,
                    expected_player_revision,
                    None,
                    0,
                    -purchase.total,
                    purchase.player.level,
                    purchase.player.experience,
                    purchase.player.currency,
                    player_revision,
                )
                if player_mutation is None or tuple(player_mutation) != expected_player_mutation:
                    raise ShopStoreError(
                        "shop purchase does not match its player mutation"
                    )

                inventory_mutation = self.db.execute(
                    """SELECT character_id, expected_revision, payload_json,
                              result_json, result_revision
                       FROM inventory_mutations WHERE request_id=?""",
                    (internal_request_id,),
                ).fetchone()
                if inventory_mutation is None:
                    raise ShopStoreError(
                        "shop purchase inventory mutation is missing"
                    )
                (mutation_character_id, mutation_expected_revision,
                 mutation_payload_json, mutation_result_json,
                 mutation_result_revision) = inventory_mutation
                if (mutation_character_id != character_id
                        or type(mutation_expected_revision) is not int
                        or mutation_expected_revision != expected_inventory_revision
                        or type(mutation_result_revision) is not int
                        or mutation_result_revision != inventory_revision
                        or type(mutation_payload_json) is not str
                        or len(mutation_payload_json) > 512 * 1024
                        or not mutation_payload_json.isascii()):
                    raise ShopStoreError("invalid shop inventory mutation metadata")

                try:
                    mutation_payload = json.loads(
                        mutation_payload_json, parse_constant=reject_constant
                    )
                except (TypeError, ValueError, RecursionError) as exc:
                    raise ShopStoreError(
                        "invalid shop inventory mutation payload"
                    ) from exc
                if (type(mutation_payload) is not list
                        or len(mutation_payload) != 1
                        or type(mutation_payload[0]) is not list
                        or len(mutation_payload[0]) != 2):
                    raise ShopStoreError("invalid shop inventory mutation payload")
                item_id, item_quantity = mutation_payload[0]
                if (type(item_id) is not str
                        or not _ID_PATTERN.fullmatch(item_id)
                        or type(item_quantity) is not int
                        or item_quantity != quantity
                        or json.dumps(
                            mutation_payload,
                            separators=(",", ":"),
                            ensure_ascii=True,
                        ) != mutation_payload_json):
                    raise ShopStoreError("shop inventory mutation payload mismatch")

                try:
                    mutation_snapshot = SqliteInventoryStore._decode_snapshot(
                        mutation_result_json,
                        expected_character_id=character_id,
                        expected_revision=inventory_revision,
                    )
                except (InventoryStoreError, TypeError, ValueError) as exc:
                    raise ShopStoreError(
                        "invalid shop inventory mutation result"
                    ) from exc
                if (mutation_snapshot != purchase.inventory
                        or self._encode_inventory_snapshot(mutation_snapshot)
                        != mutation_result_json):
                    raise ShopStoreError(
                        "shop purchase does not match its inventory mutation"
                    )
                purchase_count += 1

            reserved_player_mutations = self.db.execute(
                """SELECT COUNT(*) FROM player_state_mutations
                   WHERE substr(request_id, 1, 5) = 'shop-'"""
            ).fetchone()[0]
            reserved_inventory_mutations = self.db.execute(
                """SELECT COUNT(*) FROM inventory_mutations
                   WHERE substr(request_id, 1, 5) = 'shop-'"""
            ).fetchone()[0]
            if (type(reserved_player_mutations) is not int
                    or type(reserved_inventory_mutations) is not int
                    or reserved_player_mutations != purchase_count
                    or reserved_inventory_mutations != purchase_count):
                raise ShopStoreError("unpaired reserved shop mutation")

            return {
                "purchases": purchase_count,
                "linked_player_mutations": purchase_count,
                "linked_inventory_mutations": purchase_count,
            }
        except sqlite3.DatabaseError as exc:
            raise ShopStoreError(
                "shop purchase integrity check could not complete"
            ) from exc

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
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                """SELECT character_id, payload_json, result_json,
                          player_revision, inventory_revision
                   FROM shop_purchase_receipts WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:2]) != (character_id, payload_json):
                    raise ShopOperationConflict(
                        "request id reused with a different purchase"
                    )
                player_result_revision = previous[3]
                inventory_result_revision = previous[4]
                if (type(player_result_revision) is not int
                        or player_result_revision != expected_player_revision + 1
                        or type(inventory_result_revision) is not int
                        or inventory_result_revision != expected_inventory_revision + 1):
                    raise ShopStoreError("invalid shop receipt revision columns")
                result = self._decode_result(
                    previous[2],
                    replayed=True,
                    expected_character_id=character_id,
                    expected_offer_id=offer_id,
                    expected_quantity=quantity,
                    expected_player_revision=player_result_revision,
                    expected_inventory_revision=inventory_result_revision,
                )
                if owns_transaction:
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
            try:
                player = SqlitePlayerStateStore._snapshot(player_row)
            except PlayerStoreError as exc:
                raise ShopStoreError(
                    "invalid stored player snapshot"
                ) from exc
            if player.revision != expected_player_revision:
                raise ShopRevisionConflict("stale player revision")

            inventory_header = self.db.execute(
                """SELECT capacity, max_stack, revision
                   FROM inventory_snapshots WHERE character_id=?""",
                (character_id,),
            ).fetchone()
            if inventory_header is None:
                raise ShopInventoryNotFound("inventory snapshot not found")
            rows = self.db.execute(
                """SELECT item_id, quantity FROM inventory_items
                   WHERE character_id=? ORDER BY item_id""",
                (character_id,),
            ).fetchall()
            capacity, max_stack, inventory_revision = inventory_header
            try:
                inventory = SqliteInventoryStore._snapshot(
                    character_id, capacity, max_stack, inventory_revision, rows
                )
            except InventoryStoreError as exc:
                raise ShopStoreError(
                    "invalid stored inventory snapshot"
                ) from exc
            if inventory.revision != expected_inventory_revision:
                raise ShopRevisionConflict("stale inventory revision")
            if (player.revision >= _MAX_PLAYER_REVISION
                    or inventory_revision >= _MAX_INVENTORY_REVISION):
                raise ShopStoreError("revision overflow")
            if player.currency < total:
                raise ShopInsufficientFunds("insufficient balance")

            candidate = dict(inventory.items)
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
            if owns_transaction:
                self.db.commit()
            return result
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            raise
