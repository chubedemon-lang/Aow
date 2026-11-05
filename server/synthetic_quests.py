"""Bounded, immutable synthetic quest progression; NOT AOW client protocol."""
from dataclasses import dataclass, replace

MAX_COUNT = 1_000_000


def _positive(value, name):
    if type(value) is not int or not 1 <= value <= MAX_COUNT:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True)
class Quest:
    quest_id: int
    objective: str
    required: int

    def __post_init__(self):
        _positive(self.quest_id, "quest_id")
        _positive(self.required, "required")
        if not isinstance(self.objective, str) or not self.objective or len(self.objective) > 64:
            raise ValueError("invalid objective")


@dataclass(frozen=True)
class QuestProgress:
    quest: Quest
    count: int = 0
    claimed: bool = False

    def __post_init__(self):
        if type(self.count) is not int or not 0 <= self.count <= self.quest.required:
            raise ValueError("invalid progress")
        if type(self.claimed) is not bool or (self.claimed and self.count != self.quest.required):
            raise ValueError("invalid claim state")

    @property
    def completed(self):
        return self.count == self.quest.required

    def advance(self, objective, amount=1):
        if not isinstance(objective, str) or objective != self.quest.objective:
            raise ValueError("wrong objective")
        _positive(amount, "amount")
        if self.claimed:
            raise ValueError("quest already claimed")
        return replace(self, count=min(self.quest.required, self.count + amount))

    def claim(self):
        if not self.completed or self.claimed:
            raise ValueError("quest not claimable")
        return replace(self, claimed=True)


@dataclass(frozen=True)
class QuestBook:
    player_id: int
    entries: tuple[QuestProgress, ...] = ()

    def __post_init__(self):
        _positive(self.player_id, "player_id")
        if type(self.entries) is not tuple or len(self.entries) > 256:
            raise ValueError("invalid quest entries")
        ids = [entry.quest.quest_id for entry in self.entries]
        if any(type(entry) is not QuestProgress for entry in self.entries) or len(set(ids)) != len(ids):
            raise ValueError("duplicate or invalid quest entries")

    def add(self, quest):
        if type(quest) is not Quest or len(self.entries) >= 256:
            raise ValueError("invalid quest")
        if any(entry.quest.quest_id == quest.quest_id for entry in self.entries):
            raise ValueError("quest already exists")
        return replace(self, entries=self.entries + (QuestProgress(quest),))

    def _change(self, quest_id, method, *args):
        _positive(quest_id, "quest_id")
        found = False
        entries = []
        for entry in self.entries:
            if entry.quest.quest_id == quest_id:
                found = True
                entry = getattr(entry, method)(*args)
            entries.append(entry)
        if not found:
            raise ValueError("unknown quest")
        return replace(self, entries=tuple(entries))

    def advance(self, quest_id, objective, amount=1):
        return self._change(quest_id, "advance", objective, amount)

    def claim(self, quest_id):
        return self._change(quest_id, "claim")
