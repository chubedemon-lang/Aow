"""Tests for transport-independent synthetic vitals; no APK assumptions."""
import unittest

from server.synthetic_player_vitals import PlayerVitalsError, SessionVitals, Vitals
from server.synthetic_session_lifecycle import SyntheticSession


def ready():
    session = SyntheticSession()
    session.authenticate()
    session.select_character("hero")
    return session


class SessionVitalsTests(unittest.TestCase):
    def test_damage_and_heal_are_bounded(self):
        session = ready()
        store = SessionVitals()
        self.assertEqual(store.initialize(session, 100), Vitals(100, 100))
        self.assertEqual(store.damage(session, 150).hp, 0)
        self.assertEqual(store.heal(session, 200).hp, 100)

    def test_rejects_invalid_types_and_negative_values_atomically(self):
        session = ready()
        store = SessionVitals()
        for value in (True, 0, -1, 1_000_001, 2.5):
            with self.assertRaises(PlayerVitalsError):
                store.initialize(session, value)
        store.initialize(session, 50)
        for value in (True, -1, 1_000_001, 2.5):
            with self.assertRaises(PlayerVitalsError):
                store.damage(session, value)
            self.assertEqual(store.vitals.hp, 50)

    def test_duplicate_initialization_preserves_existing_state(self):
        session = ready()
        store = SessionVitals()
        original = store.initialize(session, 40)
        with self.assertRaises(PlayerVitalsError):
            store.initialize(session, 80)
        self.assertIs(store.vitals, original)

    def test_close_revokes_state_even_on_rejected_operation(self):
        session = ready()
        store = SessionVitals()
        store.initialize(session, 20)
        session.close()
        with self.assertRaises(PlayerVitalsError):
            store.damage(session, 1)
        self.assertIsNone(store.vitals)

    def test_cross_session_cannot_reuse_vitals(self):
        first = ready()
        second = ready()
        store = SessionVitals()
        store.initialize(first, 20)
        with self.assertRaises(PlayerVitalsError):
            store.heal(second, 1)
        self.assertIsNone(store.vitals)
        self.assertEqual(store.initialize(second, 30).hp, 30)

    def test_map_transition_invalidates_epoch(self):
        session = ready()
        store = SessionVitals()
        store.initialize(session, 20)
        session.join_map("map_a")
        with self.assertRaises(PlayerVitalsError):
            store.damage(session, 1)
        self.assertIsNone(store.vitals)


if __name__ == "__main__":
    unittest.main()
