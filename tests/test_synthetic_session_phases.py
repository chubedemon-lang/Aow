"""Offline tests only; these transitions are NOT observed AOW packets."""
import unittest

from server.synthetic_session_phases import SessionPhaseError, SyntheticSessionPhases


class SessionPhaseTests(unittest.TestCase):
    def test_happy_path_and_leave(self):
        s = SyntheticSessionPhases()
        s.negotiate()
        s.authenticate(17, verified=True)
        s.enter_world()
        self.assertEqual((s.phase, s.player_id), (s.IN_WORLD, 17))
        s.leave_world()
        self.assertEqual((s.phase, s.player_id), (s.AUTHENTICATED, 17))

    def test_reject_out_of_order(self):
        s = SyntheticSessionPhases()
        for operation in (s.enter_world, s.leave_world):
            with self.assertRaises(SessionPhaseError):
                operation()
        with self.assertRaises(SessionPhaseError):
            s.authenticate(1, verified=True)
        self.assertEqual(s.phase, s.NEW)

    def test_external_verification_required(self):
        s = SyntheticSessionPhases()
        s.negotiate()
        for value in (False, None, 1, "yes"):
            with self.assertRaises(SessionPhaseError):
                s.authenticate(1, verified=value)
        self.assertIsNone(s.player_id)
        self.assertEqual(s.phase, s.NEGOTIATED)

    def test_invalid_player_id_is_atomic(self):
        s = SyntheticSessionPhases()
        s.negotiate()
        for value in (0, -1, True, 1.5, "1"):
            with self.assertRaises(SessionPhaseError):
                s.authenticate(value, verified=True)
        self.assertIsNone(s.player_id)
        self.assertEqual(s.phase, s.NEGOTIATED)

    def test_no_replay_or_duplicate_negotiation(self):
        s = SyntheticSessionPhases()
        s.negotiate()
        with self.assertRaises(SessionPhaseError):
            s.negotiate()
        s.authenticate(2, verified=True)
        with self.assertRaises(SessionPhaseError):
            s.authenticate(3, verified=True)
        self.assertEqual(s.player_id, 2)

    def test_close_revokes_identity_and_is_terminal(self):
        s = SyntheticSessionPhases()
        s.negotiate()
        s.authenticate(5, verified=True)
        s.enter_world()
        s.close()
        self.assertEqual(s.phase, s.CLOSED)
        self.assertIsNone(s.player_id)
        s.close()
        for operation in (s.negotiate, s.enter_world, s.leave_world):
            with self.assertRaises(SessionPhaseError):
                operation()


if __name__ == "__main__":
    unittest.main()
