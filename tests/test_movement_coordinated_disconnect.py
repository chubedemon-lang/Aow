"""Local-only integration tests for coordinated actor/map/session disconnect."""
import unittest

from server.synthetic_map_occupancy import MapOccupancy
from server.synthetic_map_movement_registry import MapMovementRegistry
from server.synthetic_movement import Position, MovementError
from server.synthetic_session_registry import SessionRegistry, RegistryError


class CoordinatedDisconnectTests(unittest.TestCase):
    def setUp(self):
        self.sessions = SessionRegistry()
        self.maps = MapOccupancy(self.sessions, capacity_per_map=1)
        self.movement = MapMovementRegistry(self.maps)
        for key in ("a", "b"):
            self.sessions.open(key)
            self.sessions.authenticate(key, key)
            self.sessions.select_character(key, key)
        self.maps.join("a", 7)
        self.movement.spawn("a", Position(0, 0), 2)

    def test_disconnect_closes_actor_and_releases_capacity(self):
        actor = self.movement._actors["a"]
        self.assertTrue(self.movement.disconnect("a"))
        self.assertTrue(actor.closed)
        self.assertIsNone(self.maps.join_epoch("a"))
        self.assertEqual(self.maps.members(7), frozenset())
        self.assertEqual(self.sessions.active_count, 1)
        self.maps.join("b", 7)

    def test_disconnected_actor_cannot_move(self):
        self.movement.disconnect("a")
        with self.assertRaises((RegistryError, MovementError)):
            self.movement.move("a", 1, Position(1, 0))

    def test_unknown_connection_does_not_modify_live_actor(self):
        actor = self.movement._actors["a"]
        with self.assertRaises(RegistryError):
            self.movement.disconnect("missing")
        self.assertFalse(actor.closed)
        self.assertEqual(self.maps.members(7), frozenset({"a"}))

    def test_disconnect_without_spawn(self):
        self.movement.clear("a")
        self.assertTrue(self.movement.disconnect("a"))
        self.assertEqual(self.maps.members(7), frozenset())

    def test_reuse_connection_after_disconnect(self):
        old = self.movement._actors["a"]
        self.movement.disconnect("a")
        self.sessions.open("a")
        self.sessions.authenticate("a", "new-account")
        self.sessions.select_character("a", "new-character")
        self.maps.join("a", 7)
        self.movement.spawn("a", Position(5, 5), 2)
        self.assertTrue(old.closed)
        self.assertEqual(self.movement.position("a"), Position(5, 5))


if __name__ == "__main__":
    unittest.main()
