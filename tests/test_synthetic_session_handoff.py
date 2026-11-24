"""Offline tests for local session handoff; no AOW reconnect claims."""
import unittest
from server.synthetic_session_registry import SessionRegistry, RegistryError


class SessionHandoffTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry(capacity=2)
        self.session = self.registry.open("old")
        self.registry.authenticate("old", "account-7")
        self.registry.select_character("old", "character-9")

    def test_verified_handoff_preserves_identity_and_count(self):
        transferred = self.registry.transfer_connection("old", "new", verified=True)
        self.assertIs(transferred, self.session)
        self.assertEqual(self.registry.active_count, 1)
        self.assertEqual(self.registry.get("new").snapshot.account_id, "account-7")
        with self.assertRaises(RegistryError):
            self.registry.get("old")

    def test_unverified_handoff_rejected(self):
        for verification in (False, None, 1, "true"):
            with self.assertRaises(RegistryError):
                self.registry.transfer_connection("old", "new", verified=verification)
        self.assertIs(self.registry.get("old"), self.session)

    def test_existing_target_rejected_atomically(self):
        other = self.registry.open("taken")
        with self.assertRaises(RegistryError):
            self.registry.transfer_connection("old", "taken", verified=True)
        self.assertIs(self.registry.get("old"), self.session)
        self.assertIs(self.registry.get("taken"), other)

    def test_invalid_target_and_missing_source(self):
        for target in ("", "x" * 129, 123):
            with self.assertRaises(RegistryError):
                self.registry.transfer_connection("old", target, verified=True)
        with self.assertRaises(RegistryError):
            self.registry.transfer_connection("missing", "new", verified=True)
        self.assertEqual(self.registry.active_count, 1)

    def test_handoff_then_close_releases_identity(self):
        self.registry.transfer_connection("old", "new", verified=True)
        self.assertTrue(self.registry.close("new"))
        self.assertEqual(self.registry.active_count, 0)
        self.registry.open("fresh")
        self.registry.authenticate("fresh", "account-7")


if __name__ == "__main__":
    unittest.main()
