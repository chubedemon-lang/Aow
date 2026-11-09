"""Regression tests for synthetic-only lease/session coordination."""
import unittest

from server.synthetic_connection_manager import SyntheticConnectionManager
from server.synthetic_player_lease import PlayerLeaseError
from server.synthetic_session import SessionError


class ConnectionManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = SyntheticConnectionManager()

    def authenticated(self, connection_id):
        gate = self.manager.open(connection_id)
        gate.challenge(b"nonce")
        gate.acknowledge(b"nonce")
        gate.authenticate("account-" + connection_id)
        return gate

    def test_exclusive_lease_and_close_releases(self):
        first = self.authenticated("first")
        second = self.authenticated("second")
        self.manager.select_player("first", "player")
        with self.assertRaises(PlayerLeaseError):
            self.manager.select_player("second", "player")
        self.assertEqual(self.manager.leases.owner_of("player"), "first")
        self.assertTrue(self.manager.close("first"))
        self.assertIsNone(first.session.player_id)
        self.manager.select_player("second", "player")
        self.assertEqual(second.session.player_id, "player")

    def test_reject_selection_before_authentication_without_lease(self):
        gate = self.manager.open("first")
        with self.assertRaises(SessionError):
            self.manager.select_player("first", "player")
        self.assertEqual(self.manager.leases.active_count, 0)
        gate.challenge(b"nonce")
        gate.acknowledge(b"nonce")
        with self.assertRaises(SessionError):
            self.manager.select_player("first", "player")
        self.assertEqual(self.manager.leases.active_count, 0)

    def test_failed_player_selection_does_not_steal_lease(self):
        gate = self.authenticated("first")
        with self.assertRaises(PlayerLeaseError):
            self.manager.select_player("first", "")
        self.assertEqual(self.manager.leases.active_count, 0)
        self.assertIsNone(gate.session.player_id)

    def test_duplicate_connection_and_unknown_connection(self):
        self.manager.open("first")
        with self.assertRaises(SessionError):
            self.manager.open("first")
        with self.assertRaises(SessionError):
            self.manager.select_player("missing", "player")
        self.assertEqual(self.manager.active_connections, 1)

    def test_close_idempotent_and_reopen(self):
        self.authenticated("first")
        self.manager.select_player("first", "player")
        self.assertTrue(self.manager.close("first"))
        self.assertFalse(self.manager.close("first"))
        self.assertEqual(self.manager.leases.active_count, 0)
        self.authenticated("first")
        self.manager.select_player("first", "player")
        self.assertEqual(self.manager.leases.active_count, 1)

    def test_capacity_failure_does_not_mutate_session(self):
        manager = SyntheticConnectionManager(max_players=1)
        for conn in ("one", "two"):
            gate = manager.open(conn)
            gate.challenge(b"nonce")
            gate.acknowledge(b"nonce")
            gate.authenticate(conn)
        manager.select_player("one", "p1")
        with self.assertRaises(PlayerLeaseError):
            manager.select_player("two", "p2")
        self.assertEqual(manager.leases.active_count, 1)
        manager.close("one")
        manager.select_player("two", "p2")


if __name__ == "__main__":
    unittest.main()
