"""Session/map combat gating tests; synthetic fixtures only."""
import unittest
from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_combat import Fighter, SyntheticBattle
from server.synthetic_map_combat_gate import CombatGateError, guarded_attack

def session(player, map_id="arena"):
    s = SyntheticSession()
    s.authenticate()
    s.select_character(player)
    s.join_map(map_id)
    return s

class MapCombatGateTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = session("a"), session("b")
        self.battle = SyntheticBattle(Fighter("a", 100, 20, 0),
                                      Fighter("b", 100, 20, 0))

    def test_valid_hit_delegates_to_battle(self):
        result = guarded_attack(self.a, self.b, self.battle, 1)
        self.assertEqual(result["target_hp"], 80)
        self.assertEqual(self.battle.hp["a"], 100)

    def test_cross_map_rejected_without_mutation(self):
        self.b = session("b", "other")
        before = self.battle.snapshot()
        with self.assertRaises(CombatGateError):
            guarded_attack(self.a, self.b, self.battle, 1)
        self.assertEqual(self.battle.snapshot(), before)

    def test_self_attack_rejected(self):
        with self.assertRaises(CombatGateError):
            guarded_attack(self.a, self.a, self.battle, 1)
        self.assertEqual(self.battle.hp["a"], 100)

    def test_closed_session_rejected(self):
        self.b.close()
        with self.assertRaises(CombatGateError):
            guarded_attack(self.a, self.b, self.battle, 1)
        self.assertEqual(self.battle.hp["b"], 100)

    def test_duplicate_player_id_rejected(self):
        duplicate = session("a")
        with self.assertRaises(CombatGateError):
            guarded_attack(self.a, duplicate, self.battle, 1)

    def test_invalid_tick_and_replay_rejected(self):
        for tick in (True, -1, "1"):
            with self.subTest(tick=tick), self.assertRaises(CombatGateError):
                guarded_attack(self.a, self.b, self.battle, tick)
        guarded_attack(self.a, self.b, self.battle, 1)
        with self.assertRaises(CombatGateError):
            guarded_attack(self.b, self.a, self.battle, 1)
        self.assertEqual(self.battle.hp["a"], 100)

    def test_unregistered_fighter_rejected(self):
        outsider = session("other")
        with self.assertRaises(CombatGateError):
            guarded_attack(outsider, self.b, self.battle, 1)
        self.assertEqual(self.battle.hp["b"], 100)

if __name__ == "__main__":
    unittest.main()
