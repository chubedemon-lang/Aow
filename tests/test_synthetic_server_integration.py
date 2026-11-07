"""Cross-component synthetic server regression tests; no APK protocol assertions."""
import unittest

from server.synthetic_login_guard import LoginGuardError, SyntheticLoginGuard
from server.synthetic_session_lifecycle import (
    SessionState, SessionTransitionError, SyntheticSession,
)
from server.synthetic_health_state import HealthStateError, SyntheticHealthState


class SyntheticServerIntegrationTests(unittest.TestCase):
    def test_guard_then_session_then_map_and_health(self):
        guard = SyntheticLoginGuard(limit=2, window=10)
        session = SyntheticSession()
        self.assertTrue(guard.attempt("account_1", 0).allowed)
        self.assertEqual(session.snapshot.state, SessionState.CONNECTED)
        session.authenticate()  # Synthetic trusted authentication event, not a real login.
        guard.clear("account_1")
        session.select_character("player_1")
        session.join_map("map_1")
        health = SyntheticHealthState(100)
        self.assertEqual(health.damage(40).current, 60)
        self.assertEqual(health.compare_and_damage(1, 20).current, 40)
        session.leave_map()
        self.assertIsNone(session.snapshot.map_id)
        session.close()
        self.assertEqual(session.snapshot.state, SessionState.CLOSED)

    def test_rejected_attempt_does_not_authenticate(self):
        guard = SyntheticLoginGuard(limit=1, window=10)
        session = SyntheticSession()
        self.assertTrue(guard.attempt("account", 0).allowed)
        self.assertFalse(guard.attempt("account", 1).allowed)
        self.assertEqual(session.snapshot.state, SessionState.CONNECTED)
        with self.assertRaises(SessionTransitionError):
            session.join_map("map")
        self.assertEqual(session.snapshot.state, SessionState.CONNECTED)

    def test_invalid_transition_does_not_mutate_health_or_session(self):
        session = SyntheticSession()
        health = SyntheticHealthState(50)
        before_session, before_health = session.snapshot, health.snapshot
        with self.assertRaises(SessionTransitionError):
            session.select_character("p")
        with self.assertRaises(HealthStateError):
            health.damage(-1)
        self.assertEqual(session.snapshot, before_session)
        self.assertEqual(health.snapshot, before_health)

    def test_closed_session_cannot_reenter_map(self):
        session = SyntheticSession()
        session.authenticate()
        session.select_character("p")
        session.join_map("m")
        session.close()
        with self.assertRaises(SessionTransitionError):
            session.join_map("m")
        with self.assertRaises(SessionTransitionError):
            session.authenticate()
        self.assertEqual(session.snapshot.state, SessionState.CLOSED)

    def test_guard_clock_rollback_preserves_existing_limit(self):
        guard = SyntheticLoginGuard(limit=1, window=10)
        guard.attempt("account", 5)
        with self.assertRaises(LoginGuardError):
            guard.attempt("account", 4)
        self.assertFalse(guard.attempt("account", 6).allowed)
        self.assertTrue(guard.attempt("account", 15).allowed)


if __name__ == "__main__":
    unittest.main()
