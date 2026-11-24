"""Registry movement tests use synthetic local values only."""
import unittest
from server.synthetic_session_registry import SessionRegistry
from server.synthetic_registry_movement_gate import RegistryMovementGate, RegistryMovementError


class RegistryMovementTests(unittest.TestCase):
    def setUp(self):
        self.registry = SessionRegistry()
        self.session = self.registry.open("socket-a")
        self.registry.authenticate("socket-a", "account-a")
        self.registry.select_character("socket-a", "hero-a")
        self.gate = RegistryMovementGate()

    def test_requires_map(self):
        with self.assertRaises(RegistryMovementError):
            self.gate.move(self.registry, "socket-a", 7, 1, 2)

    def test_wrong_map_does_not_mutate(self):
        self.session.join_map(7)
        self.gate.move(self.registry, "socket-a", 7, 1, 2)
        with self.assertRaises(RegistryMovementError):
            self.gate.move(self.registry, "socket-a", 8, 3, 4)
        self.assertEqual(self.gate.position(self.registry, "socket-a"), (1, 2))

    def test_invalid_coordinates(self):
        self.session.join_map(7)
        for x in (True, 1000001, 1.5):
            with self.assertRaises(RegistryMovementError):
                self.gate.move(self.registry, "socket-a", 7, x, 0)

    def test_handoff_preserves_position(self):
        self.session.join_map(7)
        self.gate.move(self.registry, "socket-a", 7, -3, 4)
        self.registry.transfer_connection("socket-a", "socket-b", verified=True)
        self.assertEqual(self.gate.position(self.registry, "socket-b"), (-3, 4))

    def test_leave_and_rejoin_invalidates_position(self):
        self.session.join_map(7)
        self.gate.move(self.registry, "socket-a", 7, 1, 2)
        self.session.leave_map()
        self.assertIsNone(self.gate.position(self.registry, "socket-a"))
        self.session.join_map(8)
        self.assertIsNone(self.gate.position(self.registry, "socket-a"))

    def test_forget(self):
        self.session.join_map(7)
        self.gate.move(self.registry, "socket-a", 7, 1, 2)
        self.gate.forget(self.session)
        self.assertIsNone(self.gate.position(self.registry, "socket-a"))


if __name__ == "__main__":
    unittest.main()
