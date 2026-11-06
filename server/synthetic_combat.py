"""Deterministic, in-memory combat prototype; NOT an observed AOW contract.

No APK-derived stats, packet types, turn rules or damage formulas are assumed.
"""
from dataclasses import dataclass


class CombatError(ValueError):
    """Invalid combat operation."""


@dataclass(frozen=True)
class Fighter:
    fighter_id: str
    max_hp: int
    attack: int
    defense: int

    def __post_init__(self):
        if not isinstance(self.fighter_id, str) or not self.fighter_id.strip():
            raise CombatError("fighter_id required")
        for name in ("max_hp", "attack", "defense"):
            value = getattr(self, name)
            if type(value) is not int or value < (1 if name == "max_hp" else 0):
                raise CombatError("invalid fighter stat")


class SyntheticBattle:
    """Two-fighter alternating turns with replay protection.

    Single-threaded and nonpersistent. Tick numbers are per-action monotonic,
    not wall-clock timestamps. Only the active living fighter may attack.
    """

    def __init__(self, first: Fighter, second: Fighter):
        if not isinstance(first, Fighter) or not isinstance(second, Fighter):
            raise CombatError("two fighters required")
        if first.fighter_id == second.fighter_id:
            raise CombatError("duplicate fighter")
        self.fighters = {first.fighter_id: first, second.fighter_id: second}
        self.hp = {key: fighter.max_hp for key, fighter in self.fighters.items()}
        self.order = (first.fighter_id, second.fighter_id)
        self.turn = 0
        self.last_tick = -1
        self.winner = None

    def snapshot(self):
        return {"hp": dict(self.hp), "active": None if self.winner else self.order[self.turn],
                "winner": self.winner, "last_tick": self.last_tick}

    def attack(self, actor_id: str, target_id: str, tick: int):
        if self.winner is not None:
            raise CombatError("battle finished")
        if type(tick) is not int or tick <= self.last_tick:
            raise CombatError("stale or invalid tick")
        if not isinstance(actor_id, str) or not isinstance(target_id, str):
            raise CombatError("invalid fighter id")
        if actor_id != self.order[self.turn]:
            raise CombatError("not actor turn")
        if target_id not in self.fighters or target_id == actor_id:
            raise CombatError("invalid target")
        actor = self.fighters[actor_id]
        target = self.fighters[target_id]
        damage = max(1, actor.attack - target.defense)
        new_hp = max(0, self.hp[target_id] - damage)
        self.hp[target_id] = new_hp
        self.last_tick = tick
        if new_hp == 0:
            self.winner = actor_id
        else:
            self.turn = 1 - self.turn
        return {"actor": actor_id, "target": target_id, "damage": damage,
                "target_hp": new_hp, "winner": self.winner}
