"""Standalone synthetic quest progression; not derived from AOW client data."""


class QuestError(ValueError):
    pass


class QuestJournal:
    def __init__(self, targets):
        if not isinstance(targets, dict) or not targets:
            raise QuestError("targets required")
        if any(not isinstance(k, str) or not k.strip() or type(v) is not int or v < 1
               for k, v in targets.items()):
            raise QuestError("invalid quest target")
        self._targets = dict(targets)
        self._players = {}

    @staticmethod
    def _player(player):
        if not isinstance(player, str) or not player.strip():
            raise QuestError("invalid player")

    def progress(self, player, quest):
        self._player(player)
        if quest not in self._targets:
            raise QuestError("unknown quest")
        return self._players.get(player, {}).get(quest, (0, False))

    def advance(self, player, quest, amount=1):
        self._player(player)
        if quest not in self._targets:
            raise QuestError("unknown quest")
        if type(amount) is not int or amount < 1:
            raise QuestError("invalid amount")
        current, claimed = self.progress(player, quest)
        if claimed:
            raise QuestError("quest already claimed")
        updated = min(self._targets[quest], current + amount)
        self._players.setdefault(player, {})[quest] = (updated, False)
        return updated

    def claim(self, player, quest):
        current, claimed = self.progress(player, quest)
        if claimed or current < self._targets[quest]:
            raise QuestError("quest not claimable")
        self._players[player][quest] = (current, True)
        return True
