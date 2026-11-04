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
        self.assertTrue(adapter.configured)
        self.assertEqual(adapter.receive(b"ping"), "ping")
        self.assertEqual(adapter.send("pong"), b"pong")
        with self.assertRaises(TypeError):
            adapter.receive("not bytes")

    def test_payload_size_boundaries(self):
        evidence = ProtocolEvidence("a" * 64, "synthetic unit test", "test-only")
        adapter = TransportAdapter(evidence, decode=lambda raw: raw, encode=lambda msg: msg)
        from server.transport import MAX_SYNTHETIC_PAYLOAD_BYTES
        valid = b"x" * MAX_SYNTHETIC_PAYLOAD_BYTES
        self.assertEqual(adapter.receive(valid), valid)
        self.assertEqual(adapter.send(valid), valid)
        with self.assertRaises(ValueError):
            adapter.receive(valid + b"x")
        with self.assertRaises(ValueError):
            adapter.send(valid + b"x")

    def test_configured_is_not_apk_compatibility(self):
        self.assertFalse(TransportAdapter().configured)
        evidence = ProtocolEvidence("a" * 64, "synthetic test", "test-only")
        self.assertFalse(TransportAdapter(evidence).configured)

    def test_reject_non_bytes_encoded_output(self):
        evidence = ProtocolEvidence("a" * 64, "synthetic unit test", "test-only")
        adapter = TransportAdapter(evidence, decode=lambda raw: raw,
                                   encode=lambda msg: "not bytes")
        with self.assertRaises(TypeError):
            adapter.send("hello")


if __name__ == "__main__":
    unittest.main()
