"""Session-scoped synthetic inventory; not an AOW protocol contract."""
from dataclasses import dataclass
from server.synthetic_session_lifecycle import SessionState

class InventoryError(ValueError):
    pass

@dataclass(frozen=True)
class Stack:
    item_id: str
    quantity: int

class SessionInventory:
    def __init__(self, capacity=32, max_stack=999):
        if type(capacity) is not int or not 1 <= capacity <= 256:
            raise InventoryError("invalid capacity")
        if type(max_stack) is not int or not 1 <= max_stack <= 1_000_000:
            raise InventoryError("invalid stack limit")
        self.capacity, self.max_stack = capacity, max_stack
        self._session = self._epoch = self._items = None

    @property
    def items(self):
        return None if self._items is None else tuple(
            Stack(k, v) for k, v in sorted(self._items.items()))

    def sync(self, session):
        snapshot = session.snapshot
        if (session is not self._session or snapshot is not self._epoch
                or snapshot.state not in (SessionState.CHARACTER_READY, SessionState.IN_MAP)):
            self._session = self._epoch = self._items = None
        return self.items

    def initialize(self, session):
        self.sync(session)
        if session.snapshot.state is not SessionState.CHARACTER_READY:
            raise InventoryError("character not ready")
        if self._items is not None:
            raise InventoryError("already initialized")
        self._session, self._epoch, self._items = session, session.snapshot, {}
        return self.items

    def _check(self, session, item_id, quantity):
        self.sync(session)
        if self._items is None:
            raise InventoryError("inventory not initialized")
        if (not isinstance(item_id, str) or not 1 <= len(item_id) <= 128
                or not all(c.isascii() and (c.isalnum() or c in "_-") for c in item_id)):
            raise InventoryError("invalid item id")
        if type(quantity) is not int or not 1 <= quantity <= self.max_stack:
            raise InventoryError("invalid quantity")

    def add(self, session, item_id, quantity):
        self._check(session, item_id, quantity)
        previous = self._items.get(item_id, 0)
        if previous + quantity > self.max_stack:
            raise InventoryError("stack overflow")
        if previous == 0 and len(self._items) >= self.capacity:
            raise InventoryError("inventory full")
        self._items[item_id] = previous + quantity
        return self.items

    def remove(self, session, item_id, quantity):
        self._check(session, item_id, quantity)
        previous = self._items.get(item_id, 0)
        if previous < quantity:
            raise InventoryError("insufficient items")
        if previous == quantity:
            del self._items[item_id]
        else:
            self._items[item_id] = previous - quantity
        return self.items
