"""Synthetic health component, independent of any AOW wire contract."""
from dataclasses import dataclass, replace


class HealthStateError(ValueError):
    """Invalid health operation; snapshot is unchanged."""


@dataclass(frozen=True)
class HealthSnapshot:
    current: int
    maximum: int
    revision: int = 0


class SyntheticHealthState:
    """Validated bounded health state; no client/protocol assumptions."""

    def __init__(self, maximum: int):
        if type(maximum) is not int or not 1 <= maximum <= 1_000_000_000:
            raise HealthStateError("invalid maximum health")
        self._snapshot = HealthSnapshot(maximum, maximum)

    @property
    def snapshot(self) -> HealthSnapshot:
        return self._snapshot

    @staticmethod
    def _amount(amount: int) -> int:
        if type(amount) is not int or not 0 <= amount <= 1_000_000_000:
            raise HealthStateError("invalid health amount")
        return amount

    def damage(self, amount: int) -> HealthSnapshot:
        amount = self._amount(amount)
        current = self._snapshot
        self._snapshot = replace(current, current=max(0, current.current - amount),
                                 revision=current.revision + 1)
        return self._snapshot

    def heal(self, amount: int) -> HealthSnapshot:
        amount = self._amount(amount)
        current = self._snapshot
        self._snapshot = replace(current, current=min(current.maximum, current.current + amount),
                                 revision=current.revision + 1)
        return self._snapshot

    def compare_and_damage(self, expected_revision: int, amount: int) -> HealthSnapshot:
        if type(expected_revision) is not int or expected_revision != self._snapshot.revision:
            raise HealthStateError("stale health revision")
        return self.damage(amount)
