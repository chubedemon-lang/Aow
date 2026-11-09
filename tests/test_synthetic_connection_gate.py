"""Synthetic-only connection gate tests; no APK protocol assumptions."""
import unittest

from server.synthetic_connection_gate import ConnectionGate
from server.synthetic_handshake import HandshakeError
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


if __name__ == "__main__":
    unittest.main()
