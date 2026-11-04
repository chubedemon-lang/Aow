"""Synthetic player presence invariants, independent of APK transport."""
import unittest
from server.session_state import Session, SessionTransitionError
from server.player_presence import PresenceRegistry, PresenceError


class PresenceTests(unittest.TestCase):
    def setUp(self):
        self.registry = PresenceRegistry()
        self.s = Session("s1")
        self.s.authenticate("p1")

    def test_bind_enter_leave_release(self):
        self.registry.bind(self.s)
        self.s.enter_world()
        presence = self.registry.enter_map(self.s, "map-1")
        self.assertEqual(presence.map_id, "map-1")
        self.assertEqual(self.registry.get("p1").session_id, "s1")
        self.registry.leave_map(self.s)
        self.s.leave_world()
        self.registry.release(self.s)
        self.s.close()
        self.assertIsNone(self.registry.get("p1"))

    def test_unauthenticated_cannot_bind(self):
        with self.assertRaises(SessionTransitionError):
            self.registry.bind(Session("anonymous"))

    def test_duplicate_player_cannot_bind(self):
        self.registry.bind(self.s)
        second = Session("s2")
        second.authenticate("p1")
        with self.assertRaises(PresenceError):
            self.registry.bind(second)
        self.assertEqual(self.registry.get("p1").session_id, "s1")

    def test_duplicate_session_cannot_bind(self):
        self.registry.bind(self.s)
        with self.assertRaises(SessionTransitionError):
            self.registry.bind(self.s)

    def test_map_requires_world(self):
        self.registry.bind(self.s)
        with self.assertRaises(SessionTransitionError):
            self.registry.enter_map(self.s, "map")

    def test_map_reentry_requires_leave(self):
        self.registry.bind(self.s)
        self.s.enter_world()
        self.registry.enter_map(self.s, "one")
        with self.assertRaises(PresenceError):
            self.registry.enter_map(self.s, "two")
        self.assertEqual(self.registry.get("p1").map_id, "one")

    def test_invalid_map_does_not_mutate(self):
        self.registry.bind(self.s)
        self.s.enter_world()
        for invalid in ("", "x" * 129, None, 7):
            with self.assertRaises(ValueError):
                self.registry.enter_map(self.s, invalid)
        self.assertIsNone(self.registry.get("p1").map_id)

    def test_other_session_cannot_modify_presence(self):
        self.registry.bind(self.s)
        impostor = Session("s2")
        impostor.authenticate("p1")
        impostor.enter_world()
        with self.assertRaises(PresenceError):
            self.registry.enter_map(impostor, "map")
        with self.assertRaises(PresenceError):
            self.registry.release(impostor)

    def test_release_requires_bound_session(self):
        with self.assertRaises(PresenceError):
            self.registry.release(self.s)
        self.registry.bind(self.s)
        self.registry.release(self.s)
        with self.assertRaises(PresenceError):
            self.registry.release(self.s)


if __name__ == "__main__":
    unittest.main()
