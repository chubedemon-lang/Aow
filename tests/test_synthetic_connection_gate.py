"""Synthetic-only connection gate tests; no APK protocol assumptions."""
from dataclasses import FrozenInstanceError
import unittest

from server.synthetic_connection_gate import ConnectionGate, SessionSnapshot
from server.synthetic_handshake import HandshakeError, Phase as HandshakePhase
from server.synthetic_session import Phase, SessionError


class ConnectionGateTests(unittest.TestCase):
    def test_requires_handshake_before_authentication(self):
        gate = ConnectionGate()
        with self.assertRaises(SessionError):
            gate.authenticate("account")
        self.assertIsNone(gate.session.account_id)
        self.assertEqual(gate.session.phase, Phase.CONNECTED)

    def test_successful_fixture_lifecycle(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        gate.acknowledge(b"12345678")
        gate.authenticate("account")
        gate.select_player("player")
        gate.enter_map(1)
        self.assertEqual(gate.session.phase, Phase.IN_MAP)
        gate.leave_map()
        self.assertEqual(gate.session.phase, Phase.PLAYER_SELECTED)
        gate.close()
        self.assertEqual(gate.session.phase, Phase.CLOSED)
        self.assertIsNone(gate.session.account_id)
        self.assertIsNone(gate.session.player_id)

    def test_bad_nonce_revokes_connection(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        with self.assertRaises(HandshakeError):
            gate.acknowledge(b"87654321")
        self.assertEqual(gate.session.phase, Phase.CLOSED)
        with self.assertRaises(SessionError):
            gate.authenticate("account")

    def test_close_is_idempotent_and_terminal(self):
        gate = ConnectionGate()
        gate.close()
        gate.close()
        with self.assertRaises(SessionError):
            gate.challenge(b"12345678")
        with self.assertRaises(SessionError):
            gate.authenticate("account")

    def test_invalid_login_does_not_select_player(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        gate.acknowledge(b"12345678")
        with self.assertRaises(SessionError):
            gate.authenticate("")
        self.assertEqual(gate.session.phase, Phase.CONNECTED)
        with self.assertRaises(SessionError):
            gate.select_player("player")

    def test_caller_cannot_force_handshake_phase_to_bypass_gate(self):
        gate = ConnectionGate()
        with self.assertRaises(AttributeError):
            gate.handshake.phase = HandshakePhase.ESTABLISHED
        self.assertEqual(gate.handshake.phase, HandshakePhase.NEW)
        with self.assertRaises(SessionError):
            gate.authenticate("account")
        self.assertIsNone(gate.session.account_id)

    def test_session_is_a_frozen_snapshot_not_a_mutable_handle(self):
        gate = ConnectionGate()
        snapshot = gate.session
        self.assertIsInstance(snapshot, SessionSnapshot)
        self.assertFalse(hasattr(snapshot, "authenticate"))
        with self.assertRaises(FrozenInstanceError):
            snapshot.phase = Phase.AUTHENTICATED
        with self.assertRaises(FrozenInstanceError):
            snapshot.account_id = "forged-account"
        with self.assertRaises(AttributeError):
            gate.session = snapshot

        with self.assertRaises(SessionError):
            gate.authenticate("account")
        self.assertEqual(gate.session.phase, Phase.CONNECTED)

        gate.challenge(b"12345678")
        gate.acknowledge(b"12345678")
        gate.authenticate("account")
        self.assertEqual(snapshot.phase, Phase.CONNECTED)
        self.assertEqual(gate.session.phase, Phase.AUTHENTICATED)
        self.assertEqual(gate.session.account_id, "account")

    def test_handshake_handle_cannot_be_replaced(self):
        gate = ConnectionGate()
        with self.assertRaises(AttributeError):
            gate.handshake = object()
        self.assertEqual(gate.handshake.phase, HandshakePhase.NEW)
        with self.assertRaises(SessionError):
            gate.authenticate("account")


if __name__ == "__main__":
    unittest.main()
