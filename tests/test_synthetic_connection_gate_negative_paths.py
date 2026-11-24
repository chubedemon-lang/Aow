"""Additional synthetic gate negative-path regression tests (not AOW wire tests)."""
import unittest

from server.synthetic_connection_gate import ConnectionGate
from server.synthetic_handshake import HandshakeError
from server.synthetic_session import Phase, SessionError


class ConnectionGateNegativePaths(unittest.TestCase):
    def test_player_and_map_require_handshake(self):
        gate = ConnectionGate()
        with self.assertRaises(SessionError):
            gate.select_player("player")
        with self.assertRaises(SessionError):
            gate.enter_map(1)
        with self.assertRaises(SessionError):
            gate.leave_map()
        self.assertEqual(gate.session.phase, Phase.CONNECTED)

    def test_handshake_does_not_bypass_login_or_player_selection(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        gate.acknowledge(b"12345678")
        with self.assertRaises(SessionError):
            gate.enter_map(1)
        gate.authenticate("account")
        with self.assertRaises(SessionError):
            gate.enter_map(1)
        self.assertEqual(gate.session.phase, Phase.AUTHENTICATED)
        self.assertIsNone(gate.session.map_id)

    def test_repeated_challenge_does_not_reset_pending_nonce(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        with self.assertRaises(HandshakeError):
            gate.challenge(b"abcdefgh")
        gate.acknowledge(b"12345678")
        gate.authenticate("account")
        self.assertEqual(gate.session.account_id, "account")

    def test_bad_acknowledgement_type_revokes_gate(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        with self.assertRaises(HandshakeError):
            gate.acknowledge("12345678")
        self.assertEqual(gate.session.phase, Phase.CLOSED)
        with self.assertRaises(SessionError):
            gate.authenticate("account")

    def test_failed_map_transition_preserves_selected_player(self):
        gate = ConnectionGate()
        gate.challenge(b"12345678")
        gate.acknowledge(b"12345678")
        gate.authenticate("account")
        gate.select_player("player")
        with self.assertRaises(SessionError):
            gate.enter_map(True)
        self.assertEqual(gate.session.phase, Phase.PLAYER_SELECTED)
        self.assertEqual(gate.session.player_id, "player")
        self.assertIsNone(gate.session.map_id)


if __name__ == "__main__":
    unittest.main()
