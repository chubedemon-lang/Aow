import unittest

from server.evidence_ledger import EvidenceRecord, EvidenceStatus, protocol_ready


class EvidenceLedgerTests(unittest.TestCase):
    def record(self, topic="framing", status=EvidenceStatus.CANDIDATE,
               method="il2cpp_offline", reference="metadata/type:123",
               apk_sha256="a" * 64, test_run_sha256=None):
        if (status is EvidenceStatus.VERIFIED_END_TO_END
                and method == "authorized_local_test"
                and test_run_sha256 is None):
            test_run_sha256 = "c" * 64
        return EvidenceRecord(
            apk_sha256, topic, status, reference, method, test_run_sha256
        )

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

    def test_end_to_end_records_require_a_valid_test_run_digest(self):
        with self.assertRaisesRegex(ValueError, "test_run_sha256"):
            EvidenceRecord(
                "a" * 64, "framing", EvidenceStatus.VERIFIED_END_TO_END,
                "metadata/type:123", "authorized_local_test",
            )
        for invalid in ("short", "A" * 64, 7):
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                EvidenceRecord(
                    "a" * 64, "framing", EvidenceStatus.VERIFIED_END_TO_END,
                    "metadata/type:123", "authorized_local_test", invalid,
                )

    def test_readiness_cannot_combine_topics_from_different_test_runs(self):
        topics = ("transport", "framing", "serialization", "handshake", "login")
        split_runs = [
            self.record(
                topic, EvidenceStatus.VERIFIED_END_TO_END,
                "authorized_local_test", test_run_sha256=f"{index + 1:064x}",
            )
            for index, topic in enumerate(topics)
        ]
        self.assertFalse(protocol_ready(split_runs))

        one_run = [
            self.record(
                topic, EvidenceStatus.VERIFIED_END_TO_END,
                "authorized_local_test", test_run_sha256="d" * 64,
            )
            for topic in topics
        ]
        self.assertTrue(protocol_ready(one_run))

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

    def test_rejects_absolute_and_traversing_evidence_references(self):
        invalid = (
            "/mnt/data/private/aow.apk",
            "//fileserver/private/capture.pcap",
            "C:/Users/Operator/capture.pcap",
            "../private/capture.pcap",
            "docs/../private/capture.pcap",
        )
        for reference in invalid:
            with self.subTest(reference=reference), self.assertRaises(ValueError):
                self.record(reference=reference)

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


    def test_readiness_revalidates_frozen_records_at_trust_boundary(self):
        invalid_topic = self.record(
            "transport", EvidenceStatus.VERIFIED_END_TO_END,
            "authorized_local_test",
        )
        object.__setattr__(invalid_topic, "topic", "unrecognized")
        with self.assertRaisesRegex(ValueError, "invalid evidence record"):
            protocol_ready([invalid_topic])

        forged_status = self.record()
        object.__setattr__(forged_status, "status", EvidenceStatus.VERIFIED_END_TO_END)
        with self.assertRaisesRegex(ValueError, "invalid evidence record"):
            protocol_ready([forged_status])

    def test_rejects_records_list_subclass_before_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom records iterator must not run")

        with self.assertRaisesRegex(TypeError, "built-in list or tuple"):
            protocol_ready(HostileList())

    def test_rejects_record_subclass_before_attribute_access(self):
        class HostileRecord(EvidenceRecord):
            def __post_init__(self):
                pass

            def __getattribute__(self, name):
                if name in {"apk_sha256", "topic", "status", "method"}:
                    raise AssertionError("custom record accessor must not run")
                return super().__getattribute__(name)

        record = HostileRecord(
            "a" * 64, "transport", EvidenceStatus.VERIFIED_END_TO_END,
            "metadata/type:123", "authorized_local_test",
        )
        with self.assertRaisesRegex(TypeError, "exact EvidenceRecord"):
            protocol_ready([record])

    def test_rejects_required_list_subclass_before_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom required iterator must not run")

        with self.assertRaisesRegex(ValueError, "built-in list or tuple"):
            protocol_ready([], HostileList(["transport"]))

    def test_rejects_required_string_subclass_before_hashing(self):
        class HostileTopic(str):
            def __hash__(self):
                raise AssertionError("custom topic hash must not run")

            def __eq__(self, other):
                raise AssertionError("custom topic equality must not run")

        with self.assertRaisesRegex(ValueError, "exact supported topic strings"):
            protocol_ready([], (HostileTopic("transport"),))

    def test_evidence_record_rejects_string_subclasses_before_hooks(self):
        class HostileText(str):
            def __hash__(self):
                raise AssertionError("custom string hash must not run")

            def __eq__(self, other):
                raise AssertionError("custom string equality must not run")

            def __len__(self):
                raise AssertionError("custom string length must not run")

        valid = self.record()
        candidates = (
            (HostileText(valid.apk_sha256), valid.topic, valid.status,
             valid.reference, valid.method),
            (valid.apk_sha256, HostileText(valid.topic), valid.status,
             valid.reference, valid.method),
            (valid.apk_sha256, valid.topic, valid.status,
             HostileText(valid.reference), valid.method),
            (valid.apk_sha256, valid.topic, valid.status,
             valid.reference, HostileText(valid.method)),
        )
        for values in candidates:
            with self.subTest(field=values), self.assertRaises((TypeError, ValueError)):
                EvidenceRecord(*values)


if __name__ == "__main__":
    unittest.main()
