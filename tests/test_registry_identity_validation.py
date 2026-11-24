"""Synthetic registry identity validation regressions; no AOW wire claims."""
import unittest

from server.synthetic_session_registry import SessionRegistry
from server.synthetic_session_state import SessionError, Phase


class RegistryIdentityValidationTests(unittest.TestCase):
    def test_invalid_account_does_not_collide_with_unauthed_session(self):
        registry = SessionRegistry()
        registry.open("first")
        second = registry.open("second")
        for invalid in (None, "", " ", 12, True, "x" * 129):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SessionError):
                    registry.authenticate("second", invalid)
                self.assertIs(second.snapshot.phase, Phase.NEW)
        registry.authenticate("second", "valid")
        self.assertEqual(second.snapshot.account_id, "valid")

    def test_invalid_character_does_not_collide_with_unselected_session(self):
        registry = SessionRegistry()
        registry.open("first")
        registry.open("second")
        registry.authenticate("first", "a")
        registry.authenticate("second", "b")
        second = registry.get("second")
        for invalid in (None, "", " ", 12, True, "x" * 129):
            with self.subTest(invalid=invalid):
                with self.assertRaises(SessionError):
                    registry.select_character("second", invalid)
                self.assertIs(second.snapshot.phase, Phase.AUTHENTICATED)
        registry.select_character("second", "hero")
        self.assertEqual(second.snapshot.character_id, "hero")

    def test_duplicate_valid_account_still_rejected(self):
        from server.synthetic_session_registry import RegistryError
        registry = SessionRegistry()
        registry.open("a")
        registry.open("b")
        registry.authenticate("a", "same")
        with self.assertRaises(RegistryError):
            registry.authenticate("b", "same")

    def test_duplicate_valid_character_still_rejected(self):
        from server.synthetic_session_registry import RegistryError
        registry = SessionRegistry()
        registry.open("a")
        registry.open("b")
        registry.authenticate("a", "account-a")
        registry.authenticate("b", "account-b")
        registry.select_character("a", "hero")
        with self.assertRaises(RegistryError):
            registry.select_character("b", "hero")


if __name__ == "__main__":
    unittest.main()
