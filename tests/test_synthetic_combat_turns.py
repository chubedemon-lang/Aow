"""Tests for independent synthetic combat prototype (not AOW wire rules)."""
import unittest
from server.synthetic_combat import CombatError, Fighter, SyntheticBattle


class SyntheticCombatTests(unittest.TestCase):
    def setUp(self):
        self.b = SyntheticBattle(Fighter("a", 10, 5, 1), Fighter("b", 8, 3, 2))

    def test_turns_and_lethal_finish(self):
        self.assertEqual(self.b.attack("a", "b", 1)["target_hp"], 5)
        self.assertEqual(self.b.attack("b", "a", 2)["target_hp"], 8)
        self.assertIsNone(self.b.attack("a", "b", 3)["winner"])
        self.assertEqual(self.b.attack("b", "a", 4)["target_hp"], 6)
        self.assertEqual(self.b.attack("a", "b", 5)["winner"], "a")
        with self.assertRaises(CombatError):
            self.b.attack("b", "a", 6)

    def test_replay_rejected_without_mutation(self):
        self.b.attack("a", "b", 10)
        original = self.b.snapshot()
        for tick in (10, 9, True, None, "11"):
            with self.subTest(tick=tick), self.assertRaises(CombatError):
                self.b.attack("b", "a", tick)
            self.assertEqual(self.b.snapshot(), original)

    def test_bad_actor_or_target_rejected_without_mutation(self):
        before = self.b.snapshot()
        for actor, target in (("b", "a"), ("a", "a"), ("a", "missing"), ("a", []), ([], "b")):
            with self.subTest(actor=actor, target=target), self.assertRaises(CombatError):
                self.b.attack(actor, target, 1)
            self.assertEqual(self.b.snapshot(), before)

    def test_minimum_damage(self):
        b = SyntheticBattle(Fighter("a", 3, 0, 0), Fighter("b", 3, 0, 999))
        self.assertEqual(b.attack("a", "b", 0)["damage"], 1)

    def test_snapshot_is_defensive_copy(self):
        snapshot = self.b.snapshot()
        snapshot["hp"]["a"] = 0
        self.assertEqual(self.b.snapshot()["hp"]["a"], 10)

    def test_validation(self):
        for hp, attack, defense in ((True, 1, 0), (0, 1, 0), (1, -1, 0), (1, 1, False)):
            with self.subTest(hp=hp, attack=attack, defense=defense), self.assertRaises(CombatError):
                Fighter("a", hp, attack, defense)
        a = Fighter("a", 1, 1, 0)
        with self.assertRaises(CombatError):
            SyntheticBattle(a, a)

    def test_battle_isolation(self):
        other = SyntheticBattle(Fighter("a", 10, 5, 1), Fighter("b", 8, 3, 2))
        self.b.attack("a", "b", 1)
        self.assertEqual(other.snapshot()["hp"]["b"], 8)


if __name__ == "__main__":
    unittest.main()
