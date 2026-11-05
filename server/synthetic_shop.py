"""Synthetic shop domain logic, not an AOW protocol or production payment system.

Single-process, synchronous transactions only. No durable storage or concurrent writers.
"""
from dataclasses import dataclass

from server.inventory_ledger import InventoryError, InventoryLedger


class ShopError(ValueError):
    """Invalid shop transaction."""


@dataclass(frozen=True)
class ShopOffer:
    offer_id: str
    item_id: str
    unit_price: int

    def __post_init__(self):
        if not isinstance(self.offer_id, str) or not self.offer_id.strip():
            raise ShopError("offer_id required")
        if not isinstance(self.item_id, str) or not self.item_id.strip():
            raise ShopError("item_id required")
        if type(self.unit_price) is not int or self.unit_price < 1:
            raise ShopError("unit_price must be a positive integer")


class SyntheticShop:
    def __init__(self, inventory: InventoryLedger, offers: dict[str, ShopOffer],
                 max_purchase_quantity: int = 99):
        if not isinstance(inventory, InventoryLedger):
            raise ShopError("inventory ledger required")
        if type(max_purchase_quantity) is not int or max_purchase_quantity < 1:
            raise ShopError("max_purchase_quantity must be positive")
        if not isinstance(offers, dict) or any(
            not isinstance(offer, ShopOffer) or key != offer.offer_id
            for key, offer in offers.items()
        ):
            raise ShopError("offer keys must match offer IDs")
        self.inventory = inventory
        self.offers = dict(offers)
        self.max_purchase_quantity = max_purchase_quantity
        self._balances: dict[str, int] = {}

    @staticmethod
    def _player(player_id: str):
        if not isinstance(player_id, str) or not player_id.strip():
            raise ShopError("player_id required")

    def balance(self, player_id: str) -> int:
        self._player(player_id)
        return self._balances.get(player_id, 0)

    def credit(self, player_id: str, amount: int) -> int:
        self._player(player_id)
        if type(amount) is not int or amount < 1:
            raise ShopError("credit amount must be positive integer")
        self._balances[player_id] = self.balance(player_id) + amount
        return self._balances[player_id]

    def purchase(self, player_id: str, offer_id: str, quantity: int = 1) -> dict:
        self._player(player_id)
        if type(quantity) is not int or not 1 <= quantity <= self.max_purchase_quantity:
            raise ShopError("invalid purchase quantity")
        if offer_id not in self.offers:
            raise ShopError("unknown offer")
        offer = self.offers[offer_id]
        total = offer.unit_price * quantity
        current = self.balance(player_id)
        if current < total:
            raise ShopError("insufficient balance")
        # Inventory grant is atomic on validation failure. Deduct only after grant.
        try:
            items = self.inventory.grant(player_id, offer.item_id, quantity)
        except InventoryError as exc:
            raise ShopError("inventory rejected purchase") from exc
        self._balances[player_id] = current - total
        return {"balance": self._balances[player_id], "items": items,
                "offer_id": offer_id, "quantity": quantity, "total": total}
