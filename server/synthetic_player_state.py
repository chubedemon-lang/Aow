"""Server-local player progression state; NOT an AOW APK protocol model.

All operations are atomic under validation failures. No network fields are implied.
"""
from dataclasses import dataclass, replace


class PlayerStateError(ValueError):
    pass


@dataclass(frozen=True)
class PlayerSnapshot:
    character_id: str
    level: int = 1
    experience: int = 0
    currency: int = 0
    revision: int = 0


class PlayerState:
    def __init__(self, character_id: str):
        if not isinstance(character_id, str) or not character_id.strip() or len(character_id) > 128:
            raise PlayerStateError("invalid character identifier")
        self._snapshot = PlayerSnapshot(character_id)

    @property
    def snapshot(self):
        return self._snapshot

    def grant_experience(self, amount: int):
        if type(amount) is not int or not 0 <= amount <= 1_000_000:
            raise PlayerStateError("invalid experience amount")
        current = self._snapshot
        total = current.experience + amount
        level = current.level
        # Synthetic progression only, no claim about APK leveling rules.
        while total >= level * 100 and level < 100:
            total -= level * 100
            level += 1
        if level == 100:
            total = min(total, 9999)
        self._snapshot = replace(current, level=level, experience=total, revision=current.revision + 1)
        return self._snapshot

    def change_currency(self, delta: int):
        if type(delta) is not int or not -1_000_000 <= delta <= 1_000_000:
            raise PlayerStateError("invalid currency delta")
        current = self._snapshot
        balance = current.currency + delta
        if not 0 <= balance <= 2**31 - 1:
            raise PlayerStateError("insufficient funds or balance overflow")
        self._snapshot = replace(current, currency=balance, revision=current.revision + 1)
        return self._snapshot

    def compare_and_change_currency(self, expected_revision: int, delta: int):
        if type(expected_revision) is not int or expected_revision != self._snapshot.revision:
            raise PlayerStateError("stale player revision")
        return self.change_currency(delta)
