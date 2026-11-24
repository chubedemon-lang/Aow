"""Local synthetic player profile regression tests."""
import unittest

from server.synthetic_player_profiles import PlayerProfiles, PlayerProfileError
from server.synthetic_session_registry import SessionRegistry


class PlayerProfileTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.registry.open("a")
        self.registry.authenticate("a", "account")
        self.registry.select_character("a", "hero")
        self.profiles = PlayerProfiles()

    def test_profile_requires_initialization(self):
        with self.assertRaises(PlayerProfileError):
            self.profiles.get(self.registry, "a")
        self.assertEqual(self.profiles.initialize(self.registry, "a").health, 100)
        with self.assertRaises(PlayerProfileError):
            self.profiles.initialize(self.registry, "a")

    def test_mutations_are_bounded_and_atomic(self):
        self.profiles.initialize(self.registry, "a")
        for value in (True, -1, 101, 1.5):
            with self.subTest(value=value), self.assertRaises(PlayerProfileError):
                self.profiles.set_health(self.registry, "a", value)
        self.assertEqual(self.profiles.get(self.registry, "a").health, 100)
        self.assertEqual(self.profiles.set_health(self.registry, "a", 0).health, 0)
        self.assertEqual(self.profiles.grant_experience(self.registry, "a", 50).experience, 50)
        for value in (0, True, -1, 1000001):
            with self.subTest(value=value), self.assertRaises(PlayerProfileError):
                self.profiles.grant_experience(self.registry, "a", value)
        self.assertEqual(self.profiles.get(self.registry, "a").experience, 50)

    def test_verified_handoff_retains_profile(self):
        self.profiles.initialize(self.registry, "a")
        self.registry.transfer_connection("a", "b", verified=True)
        self.assertEqual(self.profiles.get(self.registry, "b").character_id, "hero")
        self.assertEqual(self.profiles.grant_experience(self.registry, "b", 1).experience, 1)

    def test_close_does_not_expose_profile_to_reused_connection(self):
        self.profiles.initialize(self.registry, "a")
        self.registry.close("a")
        self.registry.open("a")
        self.registry.authenticate("a", "account")
        self.registry.select_character("a", "hero")
        with self.assertRaises(PlayerProfileError):
            self.profiles.get(self.registry, "a")

    def test_unselected_session_is_rejected(self):
        self.registry.open("b")
        with self.assertRaises(PlayerProfileError):
            self.profiles.initialize(self.registry, "b")

    def test_explicit_forget(self):
        session = self.registry.get("a")
        self.profiles.initialize(self.registry, "a")
        self.profiles.forget(session)
        with self.assertRaises(PlayerProfileError):
            self.profiles.get(self.registry, "a")


if __name__ == "__main__":
    unittest.main()
