"""Transport-independent quest progress with session epoch isolation.

Synthetic domain model only; not evidence of AOW quest IDs or wire formats.
"""
from dataclasses import dataclass
from server.synthetic_session_lifecycle import SessionState


class QuestError(ValueError):
    pass


@dataclass(frozen=True)
class Quest:
    quest_id: str
    target: int


@dataclass(frozen=True)
class Progress:
    quest_id: str
    count: int
    target: int
    completed: bool


class SessionQuests:
    def __init__(self, quests):
        definitions = {}
        for quest in quests:
            if (not isinstance(quest, Quest)
                    or not isinstance(quest.quest_id, str)
                    or not 1 <= len(quest.quest_id) <= 128
                    or not all(c.isascii() and (c.isalnum() or c in "_-")
                               for c in quest.quest_id)
                    or type(quest.target) is not int
                    or not 1 <= quest.target <= 1_000_000
                    or quest.quest_id in definitions):
                raise QuestError("invalid or duplicate quest")
            definitions[quest.quest_id] = quest.target
        self._definitions = definitions
        self._session = self._epoch = self._counts = None

    @property
    def progress(self):
        if self._counts is None:
            return None
        return tuple(Progress(q, self._counts[q], target,
                              self._counts[q] == target)
                     for q, target in sorted(self._definitions.items()))

    def sync(self, session):
        snapshot = session.snapshot
        if (session is not self._session or snapshot is not self._epoch
                or snapshot.state not in (SessionState.CHARACTER_READY,
                                          SessionState.IN_MAP)):
            self._session = self._epoch = self._counts = None
        return self.progress

    def initialize(self, session):
        self.sync(session)
        if session.snapshot.state is not SessionState.CHARACTER_READY:
            raise QuestError("character not ready")
        if self._counts is not None:
            raise QuestError("already initialized")
        self._session, self._epoch = session, session.snapshot
        self._counts = {quest_id: 0 for quest_id in self._definitions}
        return self.progress

    def advance(self, session, quest_id, amount=1):
        self.sync(session)
        if self._counts is None:
            raise QuestError("quests not initialized")
        if (not isinstance(quest_id, str) or quest_id not in self._definitions
                or type(amount) is not int or not 1 <= amount <= 1_000_000):
            raise QuestError("invalid quest update")
        target = self._definitions[quest_id]
        self._counts[quest_id] = min(target, self._counts[quest_id] + amount)
        return self.progress
