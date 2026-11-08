"""Synthetic session handoff lifecycle regressions (no APK protocol assertions)."""
import unittest

from server.synthetic_session_registry import RegistryError, SessionRegistry
from server.synthetic_session_state import Phase


class HandoffLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(capacity=2)
        self.session = self.registry.open("socket-a")
        self.registry.authenticate("socket-a", "account-a")
        self.registry.select_character("socket-a", "hero-a")
        self.session.join_map(42)

    def test_handoff_in_map_preserves_world_state(self):
        moved = self.registry.transfer_connection("socket-a", "socket-b", verified=True)
        self.assertIs(moved, self.session)
        self.assertEqual(moved.snapshot.phase, Phase.IN_MAP)
        self.assertEqual(moved.snapshot.map_id, 42)
        self.assertEqual(moved.snapshot.character_id, "hero-a")
        moved.leave_map()
        self.assertEqual(self.registry.get("socket-b").snapshot.phase, Phase.CHARACTER_SELECTED)

    def test_old_connection_cannot_close_transferred_session(self):
        self.registry.transfer_connection("socket-a", "socket-b", verified=True)
        self.assertFalse(self.registry.close("socket-a"))
        self.assertIs(self.registry.get("socket-b"), self.session)
        self.assertEqual(self.session.snapshot.phase, Phase.IN_MAP)

    def test_handoff_does_not_release_account_or_character_uniqueness(self):
        self.registry.transfer_connection("socket-a", "socket-b", verified=True)
        self.registry.open("socket-c")
        with self.assertRaises(RegistryError):
            self.registry.authenticate("socket-c", "account-a")
        self.registry.authenticate("socket-c", "account-c")
        with self.assertRaises(RegistryError):
            self.registry.select_character("socket-c", "hero-a")
        self.assertEqual(self.registry.get("socket-c").snapshot.phase, Phase.AUTHENTICATED)

    def test_repeated_handoff_rejects_old_source_without_mutation(self):
        self.registry.transfer_connection("socket-a", "socket-b", verified=True)
        with self.assertRaises(RegistryError):
            self.registry.transfer_connection("socket-a", "socket-c", verified=True)
        self.assertIs(self.registry.get("socket-b"), self.session)
        self.assertEqual(self.registry.active_count, 1)


if __name__ == "__main__":
    unittest.main()
