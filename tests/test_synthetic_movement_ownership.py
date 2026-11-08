"""Regression checks for synthetic movement session ownership, not AOW packets."""
import gc
import unittest
import weakref

from server.synthetic_registry_movement_gate import RegistryMovementGate
from server.synthetic_session_registry import SessionRegistry


class MovementOwnershipTests(unittest.TestCase):
    def test_closed_session_position_does_not_leak(self):
        registry = SessionRegistry()
        session = registry.open("old")
        registry.authenticate("old", "account")
        registry.select_character("old", "character")
        session.join_map(3)
        gate = RegistryMovementGate()
        gate.move(registry, "old", 3, 10, 20)
        ref = weakref.ref(session)
        registry.close("old")
        del session
        gc.collect()
        self.assertIsNone(ref())
        self.assertEqual(len(gate._positions), 0)

    def test_reused_connection_never_inherits_position(self):
        registry = SessionRegistry()
        old = registry.open("socket")
        registry.authenticate("socket", "account")
        registry.select_character("socket", "hero")
        old.join_map(7)
        gate = RegistryMovementGate()
        gate.move(registry, "socket", 7, 11, 12)
        registry.close("socket")
        new = registry.open("socket")
        registry.authenticate("socket", "account")
        registry.select_character("socket", "hero")
        new.join_map(7)
        self.assertIsNone(gate.position(registry, "socket"))


if __name__ == "__main__":
    unittest.main()
