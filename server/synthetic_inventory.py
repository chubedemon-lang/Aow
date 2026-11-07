"""Synthetic inventory only; no AOW protocol assumptions."""
class Inventory:
    def __init__(self, capacity=100):
        if type(capacity) is not int or not 1 <= capacity <= 10000:
            raise ValueError("capacity")
        self.capacity, self.stacks, self.revision = capacity, {}, 0

    def apply(self, changes, revision):
        if type(revision) is not int or revision != self.revision:
            raise ValueError("revision")
        if not isinstance(changes, dict) or not changes:
            raise ValueError("changes")
        updated = self.stacks.copy()
        for key, delta in changes.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 128 or type(delta) is not int or delta == 0:
                raise ValueError("delta")
            count = updated.get(key, 0) + delta
            if not 0 <= count <= 2147483647:
                raise ValueError("quantity")
            if count:
                updated[key] = count
            else:
                updated.pop(key, None)
        if len(updated) > self.capacity:
            raise ValueError("capacity")
        self.stacks = updated
        self.revision += 1
        return self.revision
