"""Synthetic same-map combat guard regressions; no APK-derived assumptions."""
import unittest
from server.synthetic_session_lifecycle import SyntheticSession
from server.synthetic_player_vitals import SessionVitals
from server.synthetic_map_combat_gate import CombatGateError, apply_hit

def ready(player, map_id="arena"):
    s = SyntheticSession()
    s.authenticate()
    s.select_character(player)
    v = SessionVitals()
    v.initialize(s, 100)
    s.join_map(map_id)
    return s, v

class MapCombatGateTests(unittest.TestCase):
    def setUp(self):
        self.a, self.av = ready("a")
        self.b, self.bv = ready("b")

    def test_hit_updates_target_only(self):
        hit = apply_hit(self.a, self.b, self.bv, 25)
        self.assertEqual((hit.attacker_id, hit.target_id, hit.remaining_hp), ("a", "b", 75))
        self.assertEqual(self.av.vitals.hp, 100)

    def test_cross_map_rejected_unchanged(self):
        self.b.leave_map()
        self.b.join_map("other")
        with self.assertRaises(CombatGateError):
            apply_hit(self.a, self.b, self.bv, 5)
        self.assertEqual(self.bv.vitals.hp, 100)

    def test_self_attack_rejected(self):
        with self.assertRaises(CombatGateError):
            apply_hit(self.a, self.a, self.av, 10)
        self.assertEqual(self.av.vitals.hp, 100)

    def test_invalid_damage_never_changes_hp(self):
        for amount in (True, 0, -1, 1_000_001, "10"):
            with self.subTest(amount=amount), self.assertRaises(CombatGateError):
                apply_hit(self.a, self.b, self.bv, amount)
        self.assertEqual(self.bv.vitals.hp, 100)

    def test_closed_target_rejected(self):
        self.b.close()
        with self.assertRaises(CombatGateError):
            apply_hit(self.a, self.b, self.bv, 10)
        self.assertIsNone(self.bv.sync(self.b))

    def test_defeated_target_cannot_be_hit_again(self):
        self.assertEqual(apply_hit(self.a, self.b, self.bv, 200).remaining_hp, 0)
        with self.assertRaises(CombatGateError):
            apply_hit(self.a, self.b, self.bv, 1)
        self.assertEqual(self.bv.vitals.hp, 0)

    def test_same_player_id_different_sessions_rejected(self):
        duplicate, duplicate_vitals = ready("a")
        with self.assertRaises(CombatGateError):
            apply_hit(self.a, duplicate, duplicate_vitals, 1)
        self.assertEqual(duplicate_vitals.vitals.hp, 100)

if __name__ == "__main__":
    unittest.main()
