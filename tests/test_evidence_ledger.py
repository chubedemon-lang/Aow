import unittest

from server.evidence_ledger import EvidenceRecord, EvidenceStatus, protocol_ready


class EvidenceLedgerTests(unittest.TestCase):
    def record(self, topic="framing", status=EvidenceStatus.CANDIDATE,
               method="il2cpp_offline", reference="metadata/type:123"):
        return EvidenceRecord("a" * 64, topic, status, reference, method)

    def test_candidate_cannot_claim_compatibility(self):
        self.assertFalse(protocol_ready([self.record()]))

    def test_offline_verified_still_not_end_to_end(self):
        records = [self.record(topic, EvidenceStatus.VERIFIED_OFFLINE)
                   for topic in ("transport", "framing", "handshake", "login")]
        self.assertFalse(protocol_ready(records))

    def test_complete_authorized_local_evidence(self):
        records = [self.record(topic, EvidenceStatus.VERIFIED_END_TO_END,
                               "authorized_local_test")
                   for topic in ("transport", "framing", "handshake", "login")]
        self.assertTrue(protocol_ready(records))
        self.assertFalse(protocol_ready(records[:-1]))

    def test_reject_raw_endpoint_or_secret_like_reference(self):
        for ref in ("https://official.example/path", "token=secret", "raw packet 00 01"):
            with self.subTest(ref=ref), self.assertRaises(ValueError):
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

    def test_cannot_combine_evidence_from_different_apks(self):
        topics = ("transport", "framing", "handshake", "login")
        records = [self.record(topic, EvidenceStatus.VERIFIED_END_TO_END,
                               "authorized_local_test") for topic in topics[:-1]]
        records.append(EvidenceRecord("b" * 64, "login",
                                      EvidenceStatus.VERIFIED_END_TO_END,
                                      "local/test:1", "authorized_local_test"))
        self.assertFalse(protocol_ready(records))
        records.append(self.record("login", EvidenceStatus.VERIFIED_END_TO_END,
                                   "authorized_local_test"))
        self.assertTrue(protocol_ready(records))

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
