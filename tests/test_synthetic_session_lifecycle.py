"""Synthetic lifecycle tests; no APK protocol compatibility implied."""
import unittest

from server.synthetic_session_lifecycle import (
    SessionState, SessionTransitionError, SyntheticSession
)


class _HostileIdentifier(str):
    def __len__(self):
        raise AssertionError("custom string length hook must not execute")

    def __iter__(self):
        raise AssertionError("custom string iterator must not execute")


class SessionLifecycleTests(unittest.TestCase):
    def test_happy_path_and_reentry(self):
        s = SyntheticSession()
        self.assertEqual(s.snapshot.state, SessionState.CONNECTED)
        s.authenticate()
        s.select_character("player_1")
        s.join_map("map_2")
        self.assertEqual(s.snapshot.map_id, "map_2")
        s.leave_map()
        self.assertIsNone(s.snapshot.map_id)
        self.assertEqual(s.snapshot.player_id, "player_1")
        s.join_map("map_3")
        self.assertEqual(s.snapshot.map_id, "map_3")

    def test_reject_out_of_order_without_mutation(self):
        s = SyntheticSession()
        original = s.snapshot
        with self.assertRaises(SessionTransitionError):
            s.join_map("test")
        self.assertEqual(s.snapshot, original)
        with self.assertRaises(SessionTransitionError):
            s.select_character("p")
        self.assertEqual(s.snapshot, original)

    def test_invalid_player_identifier_keeps_auth_state(self):
        s = SyntheticSession()
        s.authenticate()
        for bad in ("", "a/b", "é", "x" * 129, None, 1, "a b"):
            with self.subTest(bad=bad):
                with self.assertRaises(SessionTransitionError):
                    s.select_character(bad)
                self.assertEqual(s.snapshot.state, SessionState.AUTHENTICATED)

    def test_string_subclass_is_rejected_before_custom_hooks(self):
        s = SyntheticSession()
        s.authenticate()
        with self.assertRaisesRegex(SessionTransitionError, "invalid identifier"):
            s.select_character(_HostileIdentifier("player_1"))
        self.assertEqual(s.snapshot.state, SessionState.AUTHENTICATED)

        s.select_character("player_1")
        with self.assertRaisesRegex(SessionTransitionError, "invalid identifier"):
            s.join_map(_HostileIdentifier("map_1"))
        self.assertEqual(s.snapshot.state, SessionState.CHARACTER_READY)
        self.assertEqual(s.snapshot.player_id, "player_1")

    def test_invalid_map_keeps_character_state(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("p")
        for bad in ("", "../secret", "a b", "x" * 129):
            with self.subTest(bad=bad):
                with self.assertRaises(SessionTransitionError):
                    s.join_map(bad)
                self.assertEqual(s.snapshot.state, SessionState.CHARACTER_READY)

    def test_double_authentication_rejected(self):
        s = SyntheticSession()
        s.authenticate()
        with self.assertRaises(SessionTransitionError):
            s.authenticate()

    def test_cannot_select_another_character_in_map(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("p")
        s.join_map("m")
        with self.assertRaises(SessionTransitionError):
            s.select_character("other")
        self.assertEqual(s.snapshot.player_id, "p")

    def test_close_clears_identity_and_is_idempotent(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("p")
        s.join_map("m")
        s.close()
        self.assertEqual(s.snapshot.state, SessionState.CLOSED)
        self.assertIsNone(s.snapshot.player_id)
        self.assertIsNone(s.snapshot.map_id)
        self.assertEqual(s.close(), s.snapshot)

    def test_closed_session_never_reopens(self):
        s = SyntheticSession()
        s.close()
        for action in (s.authenticate, lambda: s.select_character("p"),
                       lambda: s.join_map("m"), s.leave_map):
            with self.assertRaises(SessionTransitionError):
                action()
        self.assertEqual(s.snapshot.state, SessionState.CLOSED)

    def test_mutating_returned_snapshot_cannot_change_session(self):
        s = SyntheticSession()
        s.authenticate()
        s.select_character("player_1")
        s.join_map("map_1")

        exposed = s.snapshot
        object.__setattr__(exposed, "state", SessionState.CLOSED)
        object.__setattr__(exposed, "player_id", "attacker")
        object.__setattr__(exposed, "map_id", "other_map")

        self.assertEqual(s.snapshot.state, SessionState.IN_MAP)
        self.assertEqual(s.snapshot.player_id, "player_1")
        self.assertEqual(s.snapshot.map_id, "map_1")
        self.assertEqual(s.leave_map().state, SessionState.CHARACTER_READY)


    def test_transition_return_values_are_detached(self):
        s = SyntheticSession()

        returned = s.authenticate()
        object.__setattr__(returned, "state", SessionState.CLOSED)
        self.assertEqual(s.snapshot.state, SessionState.AUTHENTICATED)

        returned = s.select_character("player_1")
        object.__setattr__(returned, "player_id", "attacker")
        self.assertEqual(s.snapshot.player_id, "player_1")

        returned = s.join_map("map_1")
        object.__setattr__(returned, "map_id", "other_map")
        self.assertEqual(s.snapshot.map_id, "map_1")

        returned = s.leave_map()
        object.__setattr__(returned, "state", SessionState.CLOSED)
        self.assertEqual(s.snapshot.state, SessionState.CHARACTER_READY)

        returned = s.close()
        object.__setattr__(returned, "state", SessionState.CONNECTED)
        self.assertEqual(s.snapshot.state, SessionState.CLOSED)


    def test_revision_changes_only_on_successful_lifecycle_transitions(self):
        s = SyntheticSession()
        self.assertEqual(s.revision, 0)
        _ = s.snapshot
        _ = s.snapshot
        self.assertEqual(s.revision, 0)

        s.authenticate()
        self.assertEqual(s.revision, 1)
        s.select_character("player_1")
        self.assertEqual(s.revision, 2)
        s.join_map("map_1")
        self.assertEqual(s.revision, 3)
        s.leave_map()
        self.assertEqual(s.revision, 4)

        with self.assertRaises(SessionTransitionError):
            s.join_map("invalid-order")
        self.assertEqual(s.revision, 4)

        s.close()
        self.assertEqual(s.revision, 5)
        s.close()
        self.assertEqual(s.revision, 5)


if __name__ == "__main__":
    unittest.main()
