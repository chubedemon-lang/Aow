"""Transport boundary tests use a synthetic codec only, never APK claims."""
import unittest

from server.transport import ProtocolEvidence, TransportAdapter, UnverifiedProtocolError


class HostileBytes(bytes):
    """A bytes subclass whose length hook must never run at the boundary."""

    def __len__(self):
        raise AssertionError("custom bytes __len__ hook executed")


def synthetic_evidence():
    return ProtocolEvidence("a" * 64, "synthetic unit test", "tests/test_transport.py")


class TransportTests(unittest.TestCase):
    def test_fail_closed_without_evidence(self):
        adapter = TransportAdapter()
        with self.assertRaises(UnverifiedProtocolError):
            adapter.receive(b"hello")
        with self.assertRaises(UnverifiedProtocolError):
            adapter.send({"hello": 1})

    def test_reject_incomplete_codec(self):
        evidence = synthetic_evidence()
        with self.assertRaises(ValueError):
            TransportAdapter(evidence, decode=lambda value: value)
        with self.assertRaises(TypeError):
            TransportAdapter(evidence, decode=1, encode=lambda value: value)
        with self.assertRaises(ValueError):
            ProtocolEvidence("bad", "test", "review")

    def test_injected_synthetic_codec(self):
        evidence = synthetic_evidence()
        adapter = TransportAdapter(evidence, decode=lambda raw: raw.decode("ascii"),
                                   encode=lambda msg: msg.encode("ascii"))
        self.assertTrue(adapter.configured)
        self.assertEqual(adapter.receive(b"ping"), "ping")
        self.assertEqual(adapter.send("pong"), b"pong")
        with self.assertRaises(TypeError):
            adapter.receive("not bytes")

    def test_payload_size_boundaries(self):
        evidence = synthetic_evidence()
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
        evidence = ProtocolEvidence("a" * 64, "synthetic test", "tests/test_transport.py")
        self.assertFalse(TransportAdapter(evidence).configured)

    def test_reject_non_bytes_encoded_output(self):
        evidence = synthetic_evidence()
        adapter = TransportAdapter(evidence, decode=lambda raw: raw,
                                   encode=lambda msg: "not bytes")
        with self.assertRaises(TypeError):
            adapter.send("hello")

    def test_accept_sanitized_local_review_references(self):
        for reference in ("tests/test_transport.py", "issue:2", "docs/PROTOCOL.md#framing"):
            with self.subTest(reference=reference):
                evidence = ProtocolEvidence("a" * 64, "static observation", reference)
                self.assertEqual(evidence.review_reference, reference)

    def test_reject_endpoint_secret_and_unbounded_review_references(self):
        invalid = (
            "https://example.invalid/path",
            "private//path",
            "token",
            "docs/PROTOCOL.md?api_key=hidden",
            "127.0.0.1:8080",
            "localhost:8765",
            "game.example.invalid:443",
            "tests/../private.py",
            "x" * 161,
            "contains whitespace",
        )
        for reference in invalid:
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                ProtocolEvidence("a" * 64, "static observation", reference)

    def test_reject_sensitive_observation_metadata(self):
        invalid = (
            "https://private.example.invalid/capture",
            "endpoint 192.0.2.10",
            "endpoint 2001:db8::1",
            "localhost:8765",
            "game.example.invalid",
            "token=do-not-publish",
            "Authorization: Bearer abcdefghijklmnop",
            "packet_bytes=00112233",
            "-----BEGIN PRIVATE KEY-----",
        )
        for observation in invalid:
            with self.subTest(observation=observation), self.assertRaises(ValueError):
                ProtocolEvidence("a" * 64, observation, "issue:2")

    def test_accept_sanitized_observation_and_local_reference(self):
        evidence = ProtocolEvidence(
            "a" * 64,
            "Static native callsite observation; endpoint and bytes omitted",
            "docs/PROTOCOL.md#framing",
        )
        self.assertEqual(evidence.review_reference, "docs/PROTOCOL.md#framing")

    def test_reject_unbounded_observation(self):
        with self.assertRaises(ValueError):
            ProtocolEvidence("a" * 64, "x" * 2001, "issue:2")

    def test_reject_hostile_bytes_subclass_before_decode(self):
        evidence = synthetic_evidence()
        calls = []
        adapter = TransportAdapter(
            evidence,
            decode=lambda raw: calls.append(raw),
            encode=lambda message: message,
        )
        with self.assertRaises(TypeError):
            adapter.receive(HostileBytes(b"payload"))
        self.assertEqual(calls, [])

    def test_reject_hostile_bytes_subclass_from_encoder_before_length_check(self):
        evidence = synthetic_evidence()
        adapter = TransportAdapter(
            evidence,
            decode=lambda raw: raw,
            encode=lambda message: HostileBytes(b"payload"),
        )
        with self.assertRaises(TypeError):
            adapter.send("message")


if __name__ == "__main__":
    unittest.main()
