"""Transport boundary tests use a synthetic codec only, never APK claims."""
import unittest

from server.transport import ProtocolEvidence, TransportAdapter, UnverifiedProtocolError


class TransportTests(unittest.TestCase):
    def test_fail_closed_without_evidence(self):
        adapter = TransportAdapter()
        with self.assertRaises(UnverifiedProtocolError):
            adapter.receive(b"hello")
        with self.assertRaises(UnverifiedProtocolError):
            adapter.send({"hello": 1})

    def test_reject_incomplete_codec(self):
        evidence = ProtocolEvidence("a" * 64, "synthetic unit test", "test-only")
        with self.assertRaises(ValueError):
            TransportAdapter(evidence, decode=lambda value: value)
        with self.assertRaises(TypeError):
            TransportAdapter(evidence, decode=1, encode=lambda value: value)
        with self.assertRaises(ValueError):
            ProtocolEvidence("bad", "test", "review")

    def test_injected_synthetic_codec(self):
        evidence = ProtocolEvidence("a" * 64, "synthetic unit test", "test-only")
        adapter = TransportAdapter(evidence, decode=lambda raw: raw.decode("ascii"),
                                   encode=lambda msg: msg.encode("ascii"))
        self.assertTrue(adapter.verified)
        self.assertEqual(adapter.receive(b"ping"), "ping")
        self.assertEqual(adapter.send("pong"), b"pong")
        with self.assertRaises(TypeError):
            adapter.receive("not bytes")

    def test_reject_non_bytes_encoded_output(self):
        evidence = ProtocolEvidence("a" * 64, "synthetic unit test", "test-only")
        adapter = TransportAdapter(evidence, decode=lambda raw: raw,
                                   encode=lambda msg: "not bytes")
        with self.assertRaises(TypeError):
            adapter.send("hello")


if __name__ == "__main__":
    unittest.main()
