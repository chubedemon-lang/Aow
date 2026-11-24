"""Local-only occupancy reconciliation regression tests (not APK wire fixtures)."""
import unittest
from unittest.mock import patch

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_session_registry import SessionRegistry


class OccupancyPruneTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.maps = MapOccupancy(self.registry, capacity_per_map=1)
        for key in ("a", "b"):
            self.registry.open(key)
            self.registry.authenticate(key, key)
            self.registry.select_character(key, key)

    def test_direct_session_close_releases_capacity(self):
        self.maps.join("a", 42)
        self.registry.close("a")
        self.assertEqual(self.maps.prune(), 1)
        self.assertFalse(self.maps.members(42))
        self.assertIsNone(self.maps.join_epoch("a"))
        self.maps.join("b", 42)
        self.assertEqual(self.maps.members(42), frozenset({"b"}))

    def test_reused_connection_id_without_map_join_is_pruned(self):
        self.maps.join("a", 42)
        self.registry.close("a")
        self.registry.open("a")
        self.registry.authenticate("a", "new-account")
        self.registry.select_character("a", "new-character")
        self.assertEqual(self.maps.prune(), 1)
        self.assertIsNone(self.maps.join_epoch("a"))
        self.assertEqual(self.registry.get("a").snapshot.map_id, None)

    def test_valid_membership_and_epoch_survive_prune(self):
        self.maps.join("a", 42)
        epoch = self.maps.join_epoch("a")
        self.assertEqual(self.maps.prune(), 0)
        self.assertEqual(self.maps.members(42), frozenset({"a"}))
        self.assertEqual(self.maps.join_epoch("a"), epoch)

    def test_prune_idempotent_after_leave(self):
        self.maps.join("a", 42)
        self.maps.leave("a")
        self.assertEqual(self.maps.prune(), 0)
        self.assertEqual(self.maps.prune(), 0)

    def test_prune_after_close_all_is_safe(self):
        self.maps.join("a", 42)
        self.registry.close_all()
        self.assertEqual(self.maps.prune(), 1)
        self.assertEqual(self.maps.prune(), 0)

    def test_members_and_epoch_hide_live_session_after_direct_leave(self):
        self.maps.join("a", 42)
        self.registry.get("a").leave_map()

        # Reads must not expose a stale live occupant before explicit pruning.
        self.assertFalse(self.maps.members(42))
        self.assertIsNone(self.maps.join_epoch("a"))
        self.assertEqual(self.maps.prune(), 1)
        self.assertEqual(self.maps.prune(), 0)

    def test_members_hide_live_session_after_direct_rejoin_on_another_map(self):
        self.maps.join("a", 42)
        session = self.registry.get("a")
        session.leave_map()
        session.join_map(99)

        # The direct registry transition did not reserve occupancy on map 99.
        self.assertFalse(self.maps.members(42))
        self.assertFalse(self.maps.members(99))
        self.assertIsNone(self.maps.join_epoch("a"))
        self.assertEqual(self.maps.prune(), 1)

    def test_prune_uses_atomic_registry_state_snapshot(self):
        self.maps.join("a", 42)
        session = self.registry.get("a")
        session.leave_map()

        # Prune must not combine a session snapshot with a separately acquired
        # connection key: a transition could occur between those two reads.
        captured_sessions = []
        original_reader = self.registry.connection_states_for

        def capture_states(sessions):
            captured_sessions.append(frozenset(sessions))
            return original_reader(sessions)

        with patch.object(
            self.registry,
            "connection_states_for",
            side_effect=capture_states,
        ) as snapshot_reader:
            with patch.object(
                self.registry,
                "connection_id_for",
                side_effect=AssertionError("prune must use an atomic state snapshot"),
            ):
                self.assertEqual(self.maps.prune(), 1)

            snapshot_reader.assert_called_once()

        self.assertEqual(captured_sessions, [frozenset({session})])

        self.assertFalse(self.maps.members(42))
        self.assertIsNone(self.maps.join_epoch("a"))

    def test_prune_preserves_closed_stale_key_for_diagnostics(self):
        self.maps.join("a", 42)
        self.registry.close("a")
        # Closed entries retain their last-known key until an explicit prune.
        self.assertEqual(self.maps.members(42), frozenset({"a"}))
        self.assertEqual(self.maps.prune(), 1)
        self.assertFalse(self.maps.members(42))


if __name__ == "__main__":
    unittest.main()
