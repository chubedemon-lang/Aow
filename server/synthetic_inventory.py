"""Independent in-memory inventory model; NOT an observed AOW wire contract.

No item IDs, stack limits or currencies are inferred from the original APK.
"""
from collections import defaultdict

MAX_CHANGES = 4096
MAX_CAPACITY = 4096
MAX_STACK_LIMIT = 2**31 - 1
MAX_ITEM_ID = 2**31 - 1


class InventoryError(ValueError):
    pass


class Inventory:
    def __init__(self, capacity=20, max_stack=99):
        if type(capacity) is not int or not 1 <= capacity <= MAX_CAPACITY:
            raise InventoryError("invalid capacity")
        if type(max_stack) is not int or not 1 <= max_stack <= MAX_STACK_LIMIT:
            raise InventoryError("invalid stack limit")
        self.capacity = capacity
        self.max_stack = max_stack
        self._items = {}

    @staticmethod
    def _validate(item_id, quantity):
        if type(item_id) is not int or not 1 <= item_id <= MAX_ITEM_ID:
            raise InventoryError("invalid item id")
        if type(quantity) is not int or quantity <= 0:
            raise InventoryError("invalid quantity")

    def snapshot(self):
        return dict(self._items)

    def count(self, item_id):
        if type(item_id) is not int or not 1 <= item_id <= MAX_ITEM_ID:
            raise InventoryError("invalid item id")
        return self._items.get(item_id, 0)

    def apply(self, changes):
        """Atomically apply signed quantities; reject overflow/underflow.

        Changes must be a list of (item_id, signed_delta) pairs. Repeated IDs
        are aggregated before validation, so input order cannot affect results.
        """
        if not isinstance(changes, (list, tuple)) or len(changes) > MAX_CHANGES:
            raise InventoryError("changes must be a sequence")
        totals = defaultdict(int)
        for entry in changes:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise InventoryError("invalid change")
            item_id, delta = entry
            if type(item_id) is not int or not 1 <= item_id <= MAX_ITEM_ID:
                raise InventoryError("invalid item id")
            if type(delta) is not int or delta == 0 or abs(delta) > MAX_STACK_LIMIT:
                raise InventoryError("invalid delta")
            totals[item_id] += delta
        candidate = self._items.copy()
        for item_id, delta in totals.items():
            updated = candidate.get(item_id, 0) + delta
            if updated < 0 or updated > self.max_stack:
                raise InventoryError("stack limit or insufficient items")
            if updated == 0:
                candidate.pop(item_id, None)
            else:
                candidate[item_id] = updated
        if len(candidate) > self.capacity:
            raise InventoryError("inventory full")
        self._items = candidate
        return self.snapshot()

    def add(self, item_id, quantity):
        self._validate(item_id, quantity)
        return self.apply([(item_id, quantity)])

    def remove(self, item_id, quantity):
        self._validate(item_id, quantity)
        return self.apply([(item_id, -quantity)])
