"""Synthetic, in-memory inventory domain model; NOT an AOW wire contract.

All changes are atomic within a single process. No persistence or concurrency guarantees.
"""
from dataclasses import dataclass


class InventoryError(ValueError):
    """Invalid inventory operation."""


@dataclass(frozen=True)
class ItemDefinition:
    item_id: str
    stack_limit: int

    def __post_init__(self):
        if not isinstance(self.item_id, str) or not self.item_id.strip():
            raise InventoryError("item_id required")
        if type(self.stack_limit) is not int or self.stack_limit < 1:
            raise InventoryError("stack_limit must be positive integer")


class InventoryLedger:
    def __init__(self, catalog: dict[str, ItemDefinition], slot_limit: int):
        if type(slot_limit) is not int or slot_limit < 1:
            raise InventoryError("slot_limit must be positive integer")
        if not isinstance(catalog, dict) or any(
            key != item.item_id for key, item in catalog.items()
        ):
            raise InventoryError("catalog keys must match definitions")
        self._catalog = dict(catalog)
        self.slot_limit = slot_limit
        self._players: dict[str, dict[str, int]] = {}

    def _validate(self, player_id: str, item_id: str, quantity: int) -> ItemDefinition:
        if not isinstance(player_id, str) or not player_id.strip():
            raise InventoryError("player_id required")
        if item_id not in self._catalog:
            raise InventoryError("unknown item")
        if type(quantity) is not int or quantity < 1:
            raise InventoryError("quantity must be positive integer")
        return self._catalog[item_id]

    def snapshot(self, player_id: str) -> dict[str, int]:
        if not isinstance(player_id, str) or not player_id.strip():
            raise InventoryError("player_id required")
        return dict(self._players.get(player_id, {}))

    def grant(self, player_id: str, item_id: str, quantity: int) -> dict[str, int]:
        definition = self._validate(player_id, item_id, quantity)
        state = self.snapshot(player_id)
        new_total = state.get(item_id, 0) + quantity
        if new_total > definition.stack_limit:
            raise InventoryError("stack limit exceeded")
        if item_id not in state and len(state) >= self.slot_limit:
            raise InventoryError("inventory full")
        state[item_id] = new_total
        self._players[player_id] = state
        return dict(state)

    def consume(self, player_id: str, item_id: str, quantity: int) -> dict[str, int]:
        self._validate(player_id, item_id, quantity)
        state = self.snapshot(player_id)
        if state.get(item_id, 0) < quantity:
            raise InventoryError("insufficient items")
        remaining = state[item_id] - quantity
        if remaining:
            state[item_id] = remaining
        else:
            del state[item_id]
        self._players[player_id] = state
        return dict(state)
