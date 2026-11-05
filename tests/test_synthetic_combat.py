"""Additional adversarial regressions for existing synthetic combat domain."""
import unittest

from server.combat import Battle, Fighter, MAX_STAT


class CombatBoundaryTests(unittest.TestCase):
    def fighters(self):
        return Fighter(1, 10, 5, 0), Fighter(2, 8, 3, 2)

    def test_attacks_are_immutable(self):
        a, b = self.fighters()
        original = Battle(a, b, 1)
        updated, event = original.attack(1)
        self.assertEqual(original.second.hp, 8)
        self.assertEqual(updated.second.hp, 5)
        self.assertEqual(event["target_id"], 2)
        self.assertEqual(updated.next_actor, 2)

    def test_wrong_actor_no_mutation(self):
        a, b = self.fighters()
        battle = Battle(a, b, 1)
        with self.assertRaises(ValueError):
            battle.attack(2)
        self.assertEqual(battle.turn, 0)

    def test_bool_actor_rejected(self):
        a, b = self.fighters()
        with self.assertRaises(ValueError):
            Battle(a, b, 1).attack(True)

    def test_minimum_damage(self):
        battle = Battle(Fighter(1, 2, 0, 0), Fighter(2, 3, 0, 99), 1)
        after, event = battle.attack(1)
        self.assertEqual(event["damage"], 1)
        self.assertEqual(after.second.hp, 2)

    def test_overkill_reports_actual_damage(self):
        battle = Battle(Fighter(1, 3, 100, 0), Fighter(2, 2, 0, 0), 1)
        after, event = battle.attack(1)
        self.assertEqual(event["damage"], 2)
        self.assertEqual(event["winner_id"], 1)
        with self.assertRaises(ValueError):
            after.attack(1)

    def test_invalid_stats(self):
        for value in (-1, True, 1.5, MAX_STAT + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Fighter(1, value, 1, 1)

    def test_duplicate_fighters(self):
        a, _ = self.fighters()
        with self.assertRaises(ValueError):
            Battle(a, a, 1)

    def test_initial_dead_fighter_rejected(self):
        with self.assertRaises(ValueError):
            Battle(Fighter(1, 0, 1, 1), Fighter(2, 1, 1, 1), 1)

    def test_turn_limit(self):
        a, b = self.fighters()
        battle = Battle(a, b, 1, turn=MAX_STAT)
        with self.assertRaises(ValueError):
            battle.attack(1)


if __name__ == "__main__":
    unittest.main()
