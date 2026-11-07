"""Regression tests for synthetic health component (not AOW client behavior)."""
import unittest

from server.synthetic_health_state import HealthStateError, SyntheticHealthState


class SyntheticHealthStateTests(unittest.TestCase):
    def test_initial_health(self):
        self.assertEqual(SyntheticHealthState(100).snapshot.current, 100)

    def test_damage_clamps_to_zero(self):
        state = SyntheticHealthState(100)
        self.assertEqual(state.damage(200).current, 0)

    def test_heal_clamps_to_maximum(self):
        state = SyntheticHealthState(100)
        state.damage(30)
        self.assertEqual(state.heal(200).current, 100)

    def test_zero_amount_increments_revision(self):
        state = SyntheticHealthState(100)
        self.assertEqual(state.damage(0).revision, 1)

    def test_rejects_bad_initial_maximum(self):
        for value in (0, -1, True, 1.5, 1_000_000_001):
            with self.subTest(value=value), self.assertRaises(HealthStateError):
                SyntheticHealthState(value)

    def test_invalid_damage_preserves_snapshot(self):
        state = SyntheticHealthState(100)
        before = state.snapshot
        for value in (-1, True, 1.5, 1_000_000_001):
            with self.subTest(value=value), self.assertRaises(HealthStateError):
                state.damage(value)
            self.assertEqual(state.snapshot, before)

    def test_invalid_heal_preserves_snapshot(self):
        state = SyntheticHealthState(100)
        before = state.snapshot
        with self.assertRaises(HealthStateError):
            state.heal(-1)
        self.assertEqual(state.snapshot, before)

    def test_stale_revision_preserves_snapshot(self):
        state = SyntheticHealthState(100)
        state.damage(10)
        before = state.snapshot
        with self.assertRaises(HealthStateError):
            state.compare_and_damage(0, 10)
        self.assertEqual(state.snapshot, before)

    def test_compare_and_damage(self):
        state = SyntheticHealthState(100)
        self.assertEqual(state.compare_and_damage(0, 25).current, 75)
        self.assertEqual(state.snapshot.revision, 1)


if __name__ == "__main__":
    unittest.main()
