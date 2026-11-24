"""Synthetic profile boundary and snapshot regression tests; no APK claims."""
import unittest

from server.synthetic_player_profiles import PlayerProfiles, PlayerProfileError
from server.synthetic_session_registry import SessionRegistry


class ProfileBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.registry.open("conn")
        self.registry.authenticate("conn", "account")
        self.registry.select_character("conn", "hero")
        self.profiles = PlayerProfiles()

    def test_invalid_initialization_never_creates_profile(self):
        for kwargs in (
            {"level": True}, {"level": 0}, {"level": 1001},
            {"level": 1.5}, {"max_health": False},
            {"max_health": 0}, {"max_health": 1000001},
            {"max_health": "100"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PlayerProfileError):
                    self.profiles.initialize(self.registry, "conn", **kwargs)
                with self.assertRaises(PlayerProfileError):
                    self.profiles.get(self.registry, "conn")

    def test_health_boundaries_and_immutable_previous_snapshot(self):
        original = self.profiles.initialize(
            self.registry, "conn", level=1000, max_health=1000000
        )
        damaged = self.profiles.set_health(self.registry, "conn", 0)
        healed = self.profiles.set_health(self.registry, "conn", 1000000)
        self.assertEqual(original.health, 1000000)
        self.assertEqual(damaged.health, 0)
        self.assertEqual(healed.health, 1000000)
        self.assertEqual(self.profiles.get(self.registry, "conn"), healed)

    def test_experience_upper_bound_is_atomic(self):
        self.profiles.initialize(self.registry, "conn")
        # Keep this bounded in runtime while exercising the arithmetic ceiling.
        for _ in range(3):
            self.profiles.grant_experience(self.registry, "conn", 1000000)
        before = self.profiles.get(self.registry, "conn")
        with self.assertRaises(PlayerProfileError):
            self.profiles.grant_experience(self.registry, "conn", 1000001)
        self.assertEqual(self.profiles.get(self.registry, "conn"), before)

    def test_handoff_rejects_stale_connection_after_transfer(self):
        self.profiles.initialize(self.registry, "conn")
        self.registry.transfer_connection("conn", "new", verified=True)
        with self.assertRaises((KeyError, ValueError)):
            self.profiles.get(self.registry, "conn")
        self.assertEqual(self.profiles.get(self.registry, "new").character_id, "hero")


if __name__ == "__main__":
    unittest.main()
