"""Synthetic same-map hit gate; NOT an observed AOW combat or wire contract."""
from dataclasses import dataclass
from server.synthetic_session_lifecycle import SessionState
from server.synthetic_player_vitals import PlayerVitalsError

class CombatGateError(ValueError):
    """Hit rejected without modifying target HP."""

@dataclass(frozen=True)
class HitResult:
    attacker_id: str
    target_id: str
    damage: int
    remaining_hp: int

def apply_hit(attacker_session, target_session, target_vitals, damage):
    """Deterministic single-threaded hit; caller must serialize concurrent actions."""
    if attacker_session is target_session:
        raise CombatGateError("self attack")
    a, t = attacker_session.snapshot, target_session.snapshot
    if (a.state is not SessionState.IN_MAP or t.state is not SessionState.IN_MAP
            or not a.map_id or a.map_id != t.map_id
            or not a.player_id or not t.player_id or a.player_id == t.player_id):
        raise CombatGateError("players not in same map")
    if type(damage) is not int or not 1 <= damage <= 1_000_000:
        raise CombatGateError("invalid damage")
    if target_vitals.sync(target_session) is None:
        raise CombatGateError("inactive target vitals")
    if target_vitals.vitals.hp == 0:
        raise CombatGateError("target already defeated")
    try:
        result = target_vitals.damage(target_session, damage)
    except PlayerVitalsError as exc:
        raise CombatGateError("hit rejected") from exc
    return HitResult(a.player_id, t.player_id, damage, result.hp)
