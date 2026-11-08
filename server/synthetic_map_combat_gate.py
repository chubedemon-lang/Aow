"""Same-map session guard around synthetic battle; NOT an AOW wire contract."""
from server.synthetic_session_lifecycle import SessionState
from server.synthetic_combat import CombatError

class CombatGateError(ValueError):
    """Combat rejected before mutating battle state."""

def guarded_attack(attacker_session, target_session, battle, tick):
    """Validate session/map binding, then delegate to single-threaded battle."""
    if attacker_session is target_session:
        raise CombatGateError("self attack")
    a, t = attacker_session.snapshot, target_session.snapshot
    if (a.state is not SessionState.IN_MAP or t.state is not SessionState.IN_MAP
            or not a.map_id or a.map_id != t.map_id
            or not a.player_id or not t.player_id or a.player_id == t.player_id):
        raise CombatGateError("players not in same map")
    if a.player_id not in battle.fighters or t.player_id not in battle.fighters:
        raise CombatGateError("fighter not in battle")
    try:
        return battle.attack(a.player_id, t.player_id, tick)
    except CombatError as exc:
        raise CombatGateError("battle rejected action") from exc
