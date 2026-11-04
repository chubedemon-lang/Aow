"""Deterministic local combat rules for server tests, NOT AOW gameplay data.

No client packet format, damage formula, skills or original game assets are assumed.
"""
from dataclasses import dataclass, replace


MAX_STAT = 1_000_000


def _stat(value, name, *, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX_STAT:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True)
class Fighter:
    fighter_id: int
    hp: int
    attack: int
    defense: int

    def __post_init__(self):
        _stat(self.fighter_id, "fighter_id", minimum=1)
        _stat(self.hp, "hp")
        _stat(self.attack, "attack")
        _stat(self.defense, "defense")


@dataclass(frozen=True)
class Battle:
    first: Fighter
    second: Fighter
    next_actor: int
    turn: int = 0

    def __post_init__(self):
        if self.first.fighter_id == self.second.fighter_id:
            raise ValueError("fighters must be distinct")
        if self.turn == 0 and (self.first.hp == 0 or self.second.hp == 0):
            raise ValueError("battle requires living fighters")
        if self.first.hp == 0 and self.second.hp == 0:
            raise ValueError("both fighters cannot be defeated")
        if self.next_actor not in (self.first.fighter_id, self.second.fighter_id):
            raise ValueError("invalid next actor")
        _stat(self.turn, "turn")

    def attack(self, actor_id):
        """Return a new battle snapshot and synthetic event; never mutate state."""
        if type(actor_id) is not int or actor_id != self.next_actor:
            raise ValueError("not this actor's turn")
        actor_is_first = actor_id == self.first.fighter_id
        attacker = self.first if actor_is_first else self.second
        target = self.second if actor_is_first else self.first
        if attacker.hp == 0 or target.hp == 0:
            raise ValueError("battle already finished")
        if self.turn >= MAX_STAT:
            raise ValueError("turn limit reached")
        damage = max(1, attacker.attack - target.defense)
        actual_damage = min(damage, target.hp)
        updated = replace(target, hp=target.hp - actual_damage)
        next_battle = replace(
            self,
            first=attacker if actor_is_first else updated,
            second=updated if actor_is_first else attacker,
            next_actor=target.fighter_id if updated.hp else actor_id,
            turn=self.turn + 1,
        )
        event = {
            "actor_id": actor_id,
            "target_id": target.fighter_id,
            "damage": actual_damage,
            "target_hp": updated.hp,
            "winner_id": actor_id if updated.hp == 0 else None,
            "turn": next_battle.turn,
        }
        return next_battle, event
