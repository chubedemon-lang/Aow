"""Local player state tests; no original APK protocol assumptions."""
import unittest

from server.synthetic_player_state import PlayerState, PlayerStateError


class PlayerStateTests(unittest.TestCase):
    def test_defaults(self):
        p = PlayerState("hero")
        self.assertEqual((p.snapshot.level, p.snapshot.experience, p.snapshot.currency), (1, 0, 0))

    def test_experience_levels_and_remainder(self):
        p = PlayerState("hero")
        p.grant_experience(350)
        self.assertEqual((p.snapshot.level, p.snapshot.experience), (3, 50))

    def test_currency_credit_debit(self):
        p = PlayerState("hero")
        p.change_currency(200)
        self.assertEqual(p.change_currency(-75).currency, 125)

    def test_failed_debit_does_not_mutate(self):
        p = PlayerState("hero")
        before = p.snapshot
        with self.assertRaises(PlayerStateError):
            p.change_currency(-1)
        self.assertEqual(p.snapshot, before)

    def test_stale_revision_rejected(self):
        p = PlayerState("hero")
        p.change_currency(10)
        before = p.snapshot
        with self.assertRaises(PlayerStateError):
            p.compare_and_change_currency(0, -5)
        self.assertEqual(p.snapshot, before)
        self.assertEqual(p.compare_and_change_currency(1, -5).currency, 5)

    def test_invalid_inputs_preserve_state(self):
        p = PlayerState("hero")
        before = p.snapshot
        for fn in (lambda: p.grant_experience(True), lambda: p.grant_experience(-1),
                   lambda: p.change_currency(1.5), lambda: p.change_currency(2**31),
                   lambda: p.compare_and_change_currency(True, 1)):
            with self.assertRaises(PlayerStateError):
                fn()
            self.assertEqual(p.snapshot, before)

    def test_character_id_validation(self):
        for value in ("", " ", None, "x" * 129):
            with self.assertRaises(PlayerStateError):
                PlayerState(value)

    def test_snapshot_immutable(self):
        from dataclasses import FrozenInstanceError
        p = PlayerState("hero")
        with self.assertRaises(FrozenInstanceError):
            p.snapshot.currency = 100


if __name__ == "__main__":
    unittest.main()
