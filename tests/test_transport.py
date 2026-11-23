"""Transport boundary tests use a synthetic codec only, never APK claims."""
import unittest
from unittest.mock import patch

import server.transport as transport_module
from server.protocol_evidence_registry import Evidence
from server.protocol_evidence_gates import STAGES, evidence_record_digest
from server.transport import (
    EvidenceGatedTransportAdapter,
    ProtocolEvidence,
    TransportAdapter,
    UnverifiedProtocolError,
)


class HostileBytes(bytes):
    """A bytes subclass whose length hook must never run at the boundary."""

    def __len__(self):
        raise AssertionError("custom bytes __len__ hook executed")


class HostileString(str):
    """A string subclass whose hooks must not run during digest validation."""

    def __len__(self):
        raise AssertionError("custom str __len__ hook executed")

    def __iter__(self):
        raise AssertionError("custom str __iter__ hook executed")


class DerivedProtocolEvidence(ProtocolEvidence):
    """A subclass used to verify the evidence boundary accepts one exact type."""


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

    def test_reject_hostile_string_digest_before_custom_hooks(self):
        with self.assertRaisesRegex(ValueError, "source_digest"):
            ProtocolEvidence(
                HostileString("a" * 64),
                "synthetic unit test",
                "tests/test_transport.py",
            )

    def test_reject_protocol_evidence_subclass(self):
        evidence = DerivedProtocolEvidence(
            "a" * 64, "synthetic unit test", "tests/test_transport.py"
        )
        with self.assertRaisesRegex(TypeError, "invalid evidence"):
            TransportAdapter(
                evidence, decode=lambda raw: raw, encode=lambda message: message
            )



def authorized_evidence(topic, artifact_sha256="a" * 64, method="authorized_local_test"):
    return Evidence(
        topic,
        artifact_sha256,
        "authorized local client observation for " + topic,
        method,
        True,
        "tests/test_transport.py",
        "python -m unittest discover -s tests -p test_transport.py -v",
    )


def approved_digests(records):
    return tuple(evidence_record_digest(record) for record in records)


class EvidenceGatedTransportTests(unittest.TestCase):
    def make_adapter(self, records, *, required_through="serialization"):
        return EvidenceGatedTransportAdapter(
            records=records,
            artifact_sha256="a" * 64,
            approved_evidence_digests=approved_digests(records),
            decode=lambda raw: raw.decode("ascii"),
            encode=lambda message: message.encode("ascii"),
            required_through=required_through,
        )

    def test_empty_evidence_blocks_with_complete_required_prefix(self):
        with self.assertRaises(UnverifiedProtocolError) as caught:
            self.make_adapter([])
        self.assertEqual(
            caught.exception.missing_stages,
            ("transport", "framing", "serialization"),
        )

    def test_static_apk_analysis_cannot_unlock_transport_codec(self):
        records = [
            authorized_evidence(stage, method="il2cpp_offline")
            for stage in ("transport", "framing", "serialization")
        ]
        with self.assertRaises(UnverifiedProtocolError) as caught:
            self.make_adapter(records)
        self.assertEqual(
            caught.exception.missing_stages,
            ("transport", "framing", "serialization"),
        )

    def test_partial_approved_prefix_reports_only_missing_stages(self):
        records = [
            authorized_evidence("transport"),
            authorized_evidence("framing"),
        ]
        with self.assertRaises(UnverifiedProtocolError) as caught:
            self.make_adapter(records)
        self.assertEqual(caught.exception.missing_stages, ("serialization",))

    def test_default_gate_requires_transport_framing_and_serialization(self):
        records = [
            authorized_evidence("transport"),
            authorized_evidence("framing"),
            authorized_evidence("serialization"),
            authorized_evidence("handshake"),
        ]
        adapter = self.make_adapter(records)
        self.assertTrue(adapter.configured)
        self.assertEqual(adapter.required_through, "serialization")
        self.assertEqual(adapter.artifact_sha256, "a" * 64)
        self.assertEqual(
            tuple(item.stage for item in adapter.gate_results),
            ("transport", "framing", "serialization"),
        )
        self.assertEqual(adapter.receive(b"ping"), "ping")
        self.assertEqual(adapter.send("pong"), b"pong")

    def test_login_gate_cannot_skip_handshake(self):
        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization", "login")
        ]
        with self.assertRaises(UnverifiedProtocolError) as caught:
            self.make_adapter(records, required_through="login")
        self.assertEqual(caught.exception.missing_stages, ("handshake",))

    def test_login_gate_requires_the_complete_ordered_prefix(self):
        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization", "handshake", "login")
        ]
        adapter = self.make_adapter(records, required_through="login")
        self.assertTrue(adapter.configured)
        self.assertEqual(adapter.required_through, "login")
        self.assertEqual(
            tuple(item.stage for item in adapter.gate_results),
            ("transport", "framing", "serialization", "handshake", "login"),
        )
        self.assertEqual(
            tuple(record.topic for record in adapter.evidence_records),
            ("transport", "framing", "serialization", "handshake", "login"),
        )

    def test_mixed_artifact_evidence_cannot_fill_a_missing_stage(self):
        records = [
            authorized_evidence("transport", artifact_sha256="a" * 64),
            authorized_evidence("framing", artifact_sha256="a" * 64),
            authorized_evidence("serialization", artifact_sha256="b" * 64),
        ]
        with self.assertRaises(UnverifiedProtocolError) as caught:
            self.make_adapter(records)
        self.assertEqual(caught.exception.missing_stages, ("serialization",))

    def test_unapproved_record_does_not_unlock_a_stage(self):
        records = [
            authorized_evidence("transport"),
            authorized_evidence("framing"),
            authorized_evidence("serialization"),
        ]
        approved = approved_digests(records[:2])
        with self.assertRaises(UnverifiedProtocolError) as caught:
            EvidenceGatedTransportAdapter(
                records=records,
                artifact_sha256="a" * 64,
                approved_evidence_digests=approved,
                decode=lambda raw: raw,
                encode=lambda message: message,
            )
        self.assertEqual(caught.exception.missing_stages, ("serialization",))

    def test_invalid_required_stage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "known protocol stage"):
            self.make_adapter([], required_through="wire_magic")

    def test_invalid_evidence_collection_is_rejected_before_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom collection iterator executed")

        with self.assertRaisesRegex(ValueError, "built-in list or tuple"):
            EvidenceGatedTransportAdapter(
                records=HostileList(),
                artifact_sha256="a" * 64,
                approved_evidence_digests=(),
                decode=lambda raw: raw,
                encode=lambda message: message,
            )

    def test_adapter_uses_one_snapshot_when_caller_collections_change_after_gate(self):
        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization")
        ]
        approvals = list(approved_digests(records))
        original_evaluate = transport_module.evaluate_evidence

        def evaluate_then_mutate(record_snapshot, **kwargs):
            result = original_evaluate(record_snapshot, **kwargs)
            # Simulate another owner changing the caller's lists after the
            # gate has evaluated them but before adapter configuration ends.
            records.clear()
            approvals.clear()
            return result

        with patch(
            "server.transport.evaluate_evidence",
            side_effect=evaluate_then_mutate,
        ):
            adapter = EvidenceGatedTransportAdapter(
                records=records,
                artifact_sha256="a" * 64,
                approved_evidence_digests=approvals,
                decode=lambda raw: raw,
                encode=lambda message: message,
            )

        self.assertTrue(adapter.configured)
        self.assertEqual(
            tuple(record.topic for record in adapter.evidence_records),
            ("transport", "framing", "serialization"),
        )
        self.assertEqual(records, [])
        self.assertEqual(approvals, [])

    def test_rejects_hostile_approval_collection_before_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom approval iterator executed")

        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization")
        ]
        with self.assertRaisesRegex(ValueError, "approved_evidence_digests"):
            EvidenceGatedTransportAdapter(
                records=records,
                artifact_sha256="a" * 64,
                approved_evidence_digests=HostileList(approved_digests(records)),
                decode=lambda raw: raw,
                encode=lambda message: message,
            )

    def test_gated_adapter_still_rejects_non_bytes_payload(self):
        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization")
        ]
        adapter = self.make_adapter(records)
        with self.assertRaises(TypeError):
            adapter.receive(bytearray(b"ping"))


    def test_adapter_uses_detached_evidence_objects_after_gate_evaluation(self):
        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization")
        ]
        approvals = list(approved_digests(records))
        original_evaluate = transport_module.evaluate_evidence

        def evaluate_then_mutate(record_snapshot, **kwargs):
            result = original_evaluate(record_snapshot, **kwargs)
            # Mutate the caller-owned frozen record after the gate has
            # evaluated its own detached copies but before adapter retention.
            object.__setattr__(records[0], "topic", "login")
            object.__setattr__(records[0], "verified", False)
            return result

        with patch(
            "server.transport.evaluate_evidence",
            side_effect=evaluate_then_mutate,
        ):
            adapter = EvidenceGatedTransportAdapter(
                records=records,
                artifact_sha256="a" * 64,
                approved_evidence_digests=approvals,
                decode=lambda raw: raw,
                encode=lambda message: message,
            )

        self.assertEqual(
            tuple(record.topic for record in adapter.evidence_records),
            ("transport", "framing", "serialization"),
        )
        self.assertEqual(
            tuple(evidence_record_digest(record) for record in adapter.evidence_records),
            tuple(approvals),
        )
        self.assertTrue(all(result.ready for result in adapter.gate_results))
        self.assertEqual(records[0].topic, "login")

    def test_adapter_evidence_and_gate_properties_return_detached_values(self):
        records = [
            authorized_evidence(stage)
            for stage in ("transport", "framing", "serialization")
        ]
        adapter = self.make_adapter(records)

        evidence_view = adapter.evidence_records
        object.__setattr__(evidence_view[0], "topic", "login")
        object.__setattr__(evidence_view[0], "verified", False)
        gate_view = adapter.gate_results
        object.__setattr__(gate_view[0], "ready", False)

        self.assertEqual(adapter.evidence_records[0].topic, "transport")
        self.assertTrue(adapter.evidence_records[0].verified)
        self.assertTrue(adapter.gate_results[0].ready)


if __name__ == "__main__":
    unittest.main()
