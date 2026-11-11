import unittest

from server.evidence_ledger import EvidenceRecord, EvidenceStatus, protocol_ready


class EvidenceLedgerTests(unittest.TestCase):
    def record(self, topic="framing", status=EvidenceStatus.CANDIDATE,
               method="il2cpp_offline", reference="metadata/type:123",
               apk_sha256="a" * 64):
        return EvidenceRecord(apk_sha256, topic, status, reference, method)

    def test_candidate_cannot_claim_compatibility(self):
        self.assertFalse(protocol_ready([self.record()]))

    def test_offline_verified_still_not_end_to_end(self):
        records = [self.record(topic, EvidenceStatus.VERIFIED_OFFLINE)
                   for topic in ("transport", "framing", "serialization",
                                 "handshake", "login")]
        self.assertFalse(protocol_ready(records))

    def test_complete_authorized_local_evidence(self):
        topics = ("transport", "framing", "serialization", "handshake", "login")
        records = [self.record(topic, EvidenceStatus.VERIFIED_END_TO_END,
                               "authorized_local_test") for topic in topics]
        self.assertTrue(protocol_ready(records))
        self.assertFalse(protocol_ready(records[:-1]))

    def test_missing_primitive_serialization_blocks_default_readiness(self):
        topics = ("transport", "framing", "handshake", "login")
        records = [self.record(topic, EvidenceStatus.VERIFIED_END_TO_END,
                               "authorized_local_test") for topic in topics]
        self.assertFalse(protocol_ready(records))
        records.append(self.record("serialization", EvidenceStatus.VERIFIED_END_TO_END,
                                   "authorized_local_test"))
        self.assertTrue(protocol_ready(records))

    def test_complete_readiness_cannot_be_assembled_from_different_apks(self):
        topics = ("transport", "framing", "serialization", "handshake", "login")
        records = [self.record(topic, EvidenceStatus.VERIFIED_END_TO_END,
                               "authorized_local_test", apk_sha256="a" * 64)
                   for topic in topics[:-1]]
        records.append(self.record("login", EvidenceStatus.VERIFIED_END_TO_END,
                                   "authorized_local_test", apk_sha256="b" * 64))
        self.assertFalse(protocol_ready(records))
        records.append(self.record("login", EvidenceStatus.VERIFIED_END_TO_END,
                                   "authorized_local_test", apk_sha256="a" * 64))
        self.assertTrue(protocol_ready(records))

    def test_reject_raw_endpoint_or_secret_like_reference(self):
        for ref in ("https://official.example/path", "token=secret", "raw packet 00 01"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.record(reference=ref)

    def test_reject_dns_ip_ipv6_localhost_and_host_port_references(self):
        examples = (
            "ftp://private.example/path",
            "file:///tmp/capture",
            "wss://private.example/socket",
            "game.example.org",
            "192.168.1.20",
            "2001:db8::1",
            "[2001:db8::1]:443",
            "localhost:8080",
            "internal-host:9000",
        )
        for ref in examples:
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                self.record(reference=ref)

    def test_accepts_local_issue_and_repository_references(self):
        for ref in ("issue:2", "docs/PROTOCOL.md#framing",
                    "metadata/type:123", "tests/test_evidence_ledger.py"):
            with self.subTest(ref=ref):
                self.record(reference=ref)

    def test_reject_unsubstantiated_e2e(self):
        with self.assertRaises(ValueError):
            self.record(status=EvidenceStatus.VERIFIED_END_TO_END)

    def test_reject_bad_digest_topic_status_and_method(self):
        with self.assertRaises(ValueError):
            EvidenceRecord("BAD", "framing", EvidenceStatus.UNKNOWN, "a:1", "jadx_offline")
        with self.assertRaises(ValueError):
            self.record(topic="made-up")
        with self.assertRaises(TypeError):
            self.record(status="verified_end_to_end")
        with self.assertRaises(ValueError):
            self.record(method="live_server_capture")

    def test_empty_or_unsupported_required_topics_fail_closed(self):
        with self.assertRaises(ValueError):
            protocol_ready([], required=())
        with self.assertRaises(ValueError):
            protocol_ready([], required=("unverified_topic",))

    def test_reject_non_record_input(self):
        with self.assertRaises(TypeError):
            protocol_ready([{"topic": "login"}])


if __name__ == "__main__":
    unittest.main()
