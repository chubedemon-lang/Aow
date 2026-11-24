"""Synthetic combat regression tests; not APK protocol assertions."""
import unittest
from dataclasses import FrozenInstanceError

from server.combat import Battle, Fighter


class CombatTests(unittest.TestCase):
    def setUp(self):
        self.a = Fighter(1, 20, 7, 2)
        self.b = Fighter(2, 10, 3, 4)

    def test_turns_damage_and_immutability(self):
        start = Battle(self.a, self.b, 1)
        after, event = start.attack(1)
        self.assertEqual((event["damage"], event["target_hp"]), (3, 7))
        self.assertEqual((start.second.hp, after.second.hp, after.next_actor), (10, 7, 2))
        after2, event2 = after.attack(2)
        self.assertEqual((event2["damage"], after2.first.hp, after2.next_actor), (1, 19, 1))
        with self.assertRaises(FrozenInstanceError):
            after.first.hp = 0

    def test_win_and_no_further_turn(self):
        battle = Battle(Fighter(1, 20, 50, 0), self.b, 1)
        finished, event = battle.attack(1)
        self.assertEqual((event["damage"], event["winner_id"], finished.second.hp), (10, 1, 0))
        with self.assertRaises(ValueError):
            finished.attack(1)

    def test_second_actor_can_win_and_terminal_state_is_stable(self):
        start = Battle(Fighter(1, 4, 1, 0), Fighter(2, 8, 9, 0), 2)
        finished, event = start.attack(2)
        self.assertEqual((finished.first.hp, finished.second.hp), (0, 8))
        self.assertEqual((event["winner_id"], event["target_hp"]), (2, 0))
        self.assertEqual(start.first.hp, 4)
        with self.assertRaises(ValueError):
            finished.attack(2)

    def test_reject_invalid_stats_and_turns(self):
        for value in (True, -1, 1_000_001, 1.5):
            with self.assertRaises(ValueError):
                Fighter(1, value, 1, 1)
        with self.assertRaises(ValueError):
            Battle(self.a, self.a, 1)
        with self.assertRaises(ValueError):
            Battle(self.a, self.b, 999)
        with self.assertRaises(ValueError):
            Battle(Fighter(1, 0, 1, 1), self.b, 2)
        with self.assertRaises(ValueError):
            Battle(self.a, self.b, 1).attack(2)
        with self.assertRaises(ValueError):
            Battle(self.a, self.b, 1).attack(True)

    def test_rejects_noncanonical_next_actor_types_before_comparison(self):
        class ExplosiveInt(int):
            def __eq__(self, other):
                raise AssertionError("custom equality hook must not run")

            def __ne__(self, other):
                raise AssertionError("custom inequality hook must not run")

        for value in (True, 1.0, ExplosiveInt(1)):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                Battle(self.a, self.b, value)

    def test_rejects_custom_turn_integer_before_terminal_comparisons(self):
        class ExplosiveInt(int):
            def __eq__(self, other):
                raise AssertionError("custom equality hook must not run")

        with self.assertRaises(ValueError):
            Battle(self.a, self.b, 1, turn=ExplosiveInt(0))

    def test_rejects_noncanonical_fighter_objects_before_attribute_access(self):
        class HostileFighter(Fighter):
            def __post_init__(self):
                # Deliberately bypass the base validation for this hostile test object.
                pass

            def __getattribute__(self, name):
                if name == "fighter_id":
                    raise AssertionError("custom fighter attribute hook must not run")
                return super().__getattribute__(name)

        hostile = HostileFighter(1, 20, 7, 2)
        invalid_pairs = (
            (hostile, self.b),
            (self.a, hostile),
            (object(), self.b),
            (self.a, None),
        )
        for first, second in invalid_pairs:
            with self.subTest(first_type=type(first).__name__, second_type=type(second).__name__):
                with self.assertRaises(ValueError):
                    Battle(first, second, 1)

    def test_defense_minimum_damage(self):
        state = Battle(Fighter(1, 3, 0, 0), Fighter(2, 3, 0, 1_000_000), 1)
        state, event = state.attack(1)
        self.assertEqual(event["damage"], 1)
        self.assertEqual(state.second.hp, 2)


if __name__ == "__main__":
    unittest.main()
