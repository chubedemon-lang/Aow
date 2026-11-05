"""Deterministic offline combat state machine; NOT AOW wire/gameplay behavior."""
from dataclasses import dataclass


class CombatError(ValueError):
    """Invalid action or state."""


@dataclass(frozen=True)
class Fighter:
    player_id: str
    max_hp: int
    attack: int
    defense: int

    def __post_init__(self):
        if not isinstance(self.player_id, str) or not self.player_id.strip():
            raise CombatError("player_id required")
        if any(type(v) is not int or v < minimum for v, minimum in
               ((self.max_hp, 1), (self.attack, 0), (self.defense, 0))):
            raise CombatError("invalid fighter stats")


class SyntheticBattle:
    """Two-player, alternating-turn combat without RNG or side effects."""

    def __init__(self, first: Fighter, second: Fighter):
        if not isinstance(first, Fighter) or not isinstance(second, Fighter):
            raise CombatError("two fighters required")
        if first.player_id == second.player_id:
            raise CombatError("fighters must differ")
        self.fighters = {first.player_id: first, second.player_id: second}
        self.hp = {p.player_id: p.max_hp for p in (first, second)}
        self.order = (first.player_id, second.player_id)
        self.turn = 0
        self.winner = None

    def snapshot(self):
        return {"hp": dict(self.hp), "turn": None if self.winner else self.order[self.turn],
                "winner": self.winner}

    def attack(self, actor: str, target: str):
        if self.winner is not None:
            raise CombatError("battle finished")
        if actor != self.order[self.turn]:
            raise CombatError("not actor's turn")
        if target not in self.fighters or actor == target:
            raise CombatError("invalid target")
        damage = max(1, self.fighters[actor].attack - self.fighters[target].defense)
        self.hp[target] = max(0, self.hp[target] - damage)
        if self.hp[target] == 0:
            self.winner = actor
        else:
            self.turn = 1 - self.turn
        return {"actor": actor, "target": target, "damage": damage,
                "remaining_hp": self.hp[target], "winner": self.winner}
