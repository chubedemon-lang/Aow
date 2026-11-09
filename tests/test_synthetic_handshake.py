"""Unit tests for a synthetic-only handshake fixture."""
import unittest

from server.synthetic_handshake import HandshakeError, Phase, SyntheticHandshake


class SyntheticHandshakeTests(unittest.TestCase):
    def test_successful_transition(self):
        state = SyntheticHandshake()
        self.assertFalse(state.established)
        state.challenge(b"12345678")
        self.assertEqual(state.phase, Phase.CHALLENGED)
        state.acknowledge(b"12345678")
        self.assertTrue(state.established)
        self.assertFalse(hasattr(state, "_nonce"))

    def test_rejects_ack_before_challenge(self):
        with self.assertRaises(HandshakeError):
            SyntheticHandshake().acknowledge(b"12345678")

    def test_rejects_bad_nonce_types_and_lengths(self):
        for nonce in (b"", b"short", b"x" * 33, bytearray(b"12345678"), "12345678"):
            with self.subTest(nonce=nonce):
                with self.assertRaises(HandshakeError):
                    SyntheticHandshake().challenge(nonce)

    def test_rejects_duplicate_challenge(self):
        state = SyntheticHandshake()
        state.challenge(b"12345678")
        with self.assertRaises(HandshakeError):
            state.challenge(b"abcdefgh")

    def test_bad_ack_closes_and_clears_nonce(self):
        state = SyntheticHandshake()
        state.challenge(b"12345678")
        with self.assertRaises(HandshakeError):
            state.acknowledge(b"abcdefgh")
        self.assertEqual(state.phase, Phase.CLOSED)
        self.assertFalse(hasattr(state, "_nonce"))
        with self.assertRaises(HandshakeError):
            state.challenge(b"12345678")

    def test_close_is_idempotent(self):
        state = SyntheticHandshake()
        state.challenge(b"12345678")
        state.close()
        state.close()
        self.assertFalse(state.established)
        self.assertFalse(hasattr(state, "_nonce"))

    def test_rejects_preestablished_initial_state(self):
        with self.assertRaises(HandshakeError):
            SyntheticHandshake(phase=Phase.ESTABLISHED)

    def test_no_replay_after_establishment(self):
        state = SyntheticHandshake()
        state.challenge(b"12345678")
        state.acknowledge(b"12345678")
        with self.assertRaises(HandshakeError):
            state.acknowledge(b"12345678")


if __name__ == "__main__":
    unittest.main()
