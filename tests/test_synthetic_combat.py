"""Regression tests for invented offline combat rules only."""
import unittest

from server.synthetic_combat import CombatError, Fighter, SyntheticBattle


class CombatTests(unittest.TestCase):
    def setUp(self):
        self.battle = SyntheticBattle(Fighter("a", 10, 5, 1), Fighter("b", 8, 3, 2))

    def test_turn_and_damage(self):
        self.assertEqual(self.battle.attack("a", "b")["remaining_hp"], 5)
        self.assertEqual(self.battle.snapshot()["turn"], "b")

    def test_wrong_turn_has_no_effect(self):
        before = self.battle.snapshot()
        with self.assertRaises(CombatError):
            self.battle.attack("b", "a")
        self.assertEqual(self.battle.snapshot(), before)

    def test_invalid_target_has_no_effect(self):
        for target in ("a", "missing"):
            with self.assertRaises(CombatError):
                self.battle.attack("a", target)
        self.assertEqual(self.battle.snapshot()["hp"]["b"], 8)

    def test_defense_minimum_damage(self):
        b = SyntheticBattle(Fighter("a", 3, 0, 0), Fighter("b", 3, 0, 100))
        self.assertEqual(b.attack("a", "b")["damage"], 1)

    def test_kill_and_no_actions_after(self):
        self.battle.attack("a", "b")
        self.battle.attack("b", "a")
        self.battle.attack("a", "b")
        self.battle.attack("b", "a")
        result = self.battle.attack("a", "b")
        self.assertEqual(result["winner"], "a")
        self.assertEqual(result["remaining_hp"], 0)
        with self.assertRaises(CombatError):
            self.battle.attack("b", "a")

    def test_invalid_stats(self):
        for stats in ((0, 1, 0), (1, -1, 0), (1, 1, -1), (True, 1, 0)):
            with self.subTest(stats=stats), self.assertRaises(CombatError):
                Fighter("a", *stats)
        with self.assertRaises(CombatError):
            Fighter("", 1, 1, 1)

    def test_duplicate_players(self):
        with self.assertRaises(CombatError):
            SyntheticBattle(Fighter("a", 1, 1, 0), Fighter("a", 1, 1, 0))

    def test_snapshot_is_copy(self):
        state = self.battle.snapshot()
        state["hp"]["a"] = -10
        self.assertEqual(self.battle.snapshot()["hp"]["a"], 10)


if __name__ == "__main__":
    unittest.main()
