"""Deterministic replay checks; no AOW packet assumptions."""
import unittest

from server.combat import Battle, Fighter
from server.combat_replay import MAX_REPLAY_ACTIONS, replay_battle


class CombatReplayTests(unittest.TestCase):
    def setUp(self):
        self.initial = Battle(Fighter(1, 20, 7, 2), Fighter(2, 10, 3, 4), 1)

    def test_replay_is_deterministic_and_does_not_mutate_input(self):
        first = replay_battle(self.initial, [1, 2, 1])
        second = replay_battle(self.initial, (1, 2, 1), expected_events=first.events)
        self.assertEqual(first, second)
        self.assertEqual(self.initial.second.hp, 10)
        self.assertEqual(first.battle.turn, 3)
        self.assertEqual(len(first.events), 3)

    def test_empty_trace_preserves_snapshot(self):
        result = replay_battle(self.initial, [])
        self.assertEqual(result.battle, self.initial)
        self.assertEqual(result.events, ())

    def test_reject_malformed_or_oversized_trace(self):
        for trace in (None, "1,2", range(2)):
            with self.assertRaises(TypeError):
                replay_battle(self.initial, trace)
        with self.assertRaises(ValueError):
            replay_battle(self.initial, [1] * (MAX_REPLAY_ACTIONS + 1))
        for actor in (True, 0, 1.5, 999999999):
            with self.assertRaises(ValueError):
                replay_battle(self.initial, [actor])

    def test_reject_wrong_turn_and_actions_after_victory(self):
        with self.assertRaises(ValueError):
            replay_battle(self.initial, [2])
        battle = Battle(Fighter(1, 20, 50, 0), Fighter(2, 10, 3, 0), 1)
        with self.assertRaises(ValueError):
            replay_battle(battle, [1, 1])

    def test_detect_divergent_events_and_bad_expected_shape(self):
        actual = replay_battle(self.initial, [1]).events
        with self.assertRaises(ValueError):
            replay_battle(self.initial, [1], expected_events=[dict(actual[0], damage=99)])
        with self.assertRaises(ValueError):
            replay_battle(self.initial, [1], expected_events=[])
        with self.assertRaises(TypeError):
            replay_battle(self.initial, [1], expected_events="invalid")


if __name__ == "__main__":
    unittest.main()
