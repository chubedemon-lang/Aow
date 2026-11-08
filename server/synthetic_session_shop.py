"""Synthetic single-threaded shop transactions; no AOW item or wire claims.

A shop is bound to one session epoch. Do not share wallet/inventory instances
across simultaneous sessions or use this adapter concurrently.
"""
from dataclasses import dataclass

from server.synthetic_session_inventory import InventoryError
from server.synthetic_session_wallet import WalletError


class ShopError(ValueError):
    pass


@dataclass(frozen=True)
class Offer:
    item_id: str
    unit_price: int


class SessionShop:
    def __init__(self, offers):
        catalog = {}
        for offer in offers:
            if not isinstance(offer, Offer):
                raise ShopError("invalid offer")
            if (not isinstance(offer.item_id, str)
                    or not 1 <= len(offer.item_id) <= 128
                    or not all(c.isascii() and (c.isalnum() or c in "_-")
                               for c in offer.item_id)
                    or type(offer.unit_price) is not int
                    or not 1 <= offer.unit_price <= 2_000_000_000
                    or offer.item_id in catalog):
                raise ShopError("invalid or duplicate offer")
            catalog[offer.item_id] = offer.unit_price
        self._prices = catalog

    def buy(self, session, wallet, inventory, item_id, quantity=1):
        # Sync both resources before evaluating a request, including failures.
        wallet.sync(session)
        inventory.sync(session)
        if (type(quantity) is not int or quantity <= 0
                or item_id not in self._prices):
            raise ShopError("invalid purchase")
        if wallet.balance is None or inventory.items is None:
            raise ShopError("uninitialized resources")
        if quantity > inventory.max_stack:
            raise ShopError("quantity exceeds stack limit")
        cost = self._prices[item_id] * quantity
        if cost > wallet.maximum or cost > wallet.balance:
            raise ShopError("insufficient funds or cost overflow")
        items = {stack.item_id: stack.quantity for stack in inventory.items}
        current = items.get(item_id, 0)
        if current + quantity > inventory.max_stack:
            raise ShopError("stack overflow")
        if current == 0 and len(items) >= inventory.capacity:
            raise ShopError("inventory full")
        # No awaits or callbacks between these two mutations. The explicit
        # rollback handles unexpected inventory rejection in this adapter.
        wallet.debit(session, cost)
        try:
            inventory.add(session, item_id, quantity)
        except InventoryError:
            wallet.credit(session, cost)
            raise ShopError("inventory rejected purchase") from None
        return wallet.balance, inventory.items
