"""Readiness gates require authorized local client evidence, not static facts alone."""
import threading
import unittest
from unittest.mock import patch

from server.protocol_evidence_registry import Evidence, EvidenceError
from server.protocol_evidence_gates import (
    STAGES,
    evaluate_evidence,
    evidence_record_digest,
)


def evidence(topic, verified=True, artifact_sha256="a" * 64,
             method="authorized_local_test"):
    return Evidence(
        topic, artifact_sha256, "offline fixture observation", method,
        verified,
        "tests/test_protocol_evidence_gates.py" if verified else None,
        (
            "python -m unittest discover -s tests -p test_protocol_evidence_gates.py -v"
            if verified else None
        ),
    )


def evaluate_approved(records, artifact_sha256=None):
    """Test helper explicitly approves these exact synthetic records."""
    approved = tuple(
        evidence_record_digest(record)
        for record in records
        if type(record) is Evidence and record.verified
    )
    return evaluate_evidence(
        records,
        artifact_sha256=artifact_sha256,
        approved_evidence_digests=approved,
    )


class EvidenceGateTests(unittest.TestCase):
    def test_empty_registry_blocks_all_stages(self):
        result = evaluate_approved([])
        self.assertEqual(len(result), len(STAGES))
        self.assertTrue(all(not item.ready for item in result))
        self.assertEqual(result[0].missing, ("transport",))

    def test_unverified_records_do_not_unlock(self):
        result = evaluate_approved([evidence("transport", False)])
        self.assertFalse(result[0].ready)

    def test_verified_flag_without_reproduction_cannot_unlock(self):
        with self.assertRaises(EvidenceError):
            Evidence("transport", "a" * 64, "offline observation", "il2cpp_offline", True)

    def test_prerequisites_required(self):
        result = {item.stage: item for item in evaluate_approved(
            [evidence("login"), evidence("framing")]
        )}
        self.assertFalse(result["login"].ready)
        self.assertEqual(result["login"].missing,
                         ("transport", "serialization", "handshake"))

    def test_verified_prefix_only(self):
        result = {item.stage: item for item in evaluate_approved(
            [evidence("transport"), evidence("framing")]
        )}
        self.assertTrue(result["transport"].ready)
        self.assertTrue(result["framing"].ready)
        self.assertFalse(result["serialization"].ready)
        self.assertFalse(result["handshake"].ready)

    def test_handshake_requires_verified_serialization_stage(self):
        topics = ("transport", "framing", "handshake")
        result = {item.stage: item for item in evaluate_approved(
            [evidence(topic) for topic in topics]
        )}
        self.assertFalse(result["serialization"].ready)
        self.assertFalse(result["handshake"].ready)
        self.assertEqual(result["handshake"].missing, ("serialization",))

    def test_all_stages_need_individual_evidence(self):
        result = evaluate_approved([evidence(topic) for topic in STAGES])
        self.assertTrue(all(item.ready for item in result))

    def test_player_and_map_are_required_before_movement(self):
        prefix = ("transport", "framing", "serialization", "handshake",
                  "login", "session", "movement")
        result = {item.stage: item for item in evaluate_approved(
            [evidence(topic) for topic in prefix]
        )}
        self.assertFalse(result["player"].ready)
        self.assertFalse(result["map"].ready)
        self.assertFalse(result["movement"].ready)
        self.assertEqual(result["movement"].missing, ("player", "map"))

    def test_invalid_collection_fails_closed(self):
        for invalid in (None, {}, [object()], [evidence("transport", False), None]):
            with self.subTest(invalid=repr(invalid)):
                with self.assertRaises(EvidenceError):
                    evaluate_evidence(invalid)

    def test_rejects_oversized_evidence_record_collection_before_scanning(self):
        records = [object()] * 4097
        with self.assertRaisesRegex(EvidenceError, "at most 4096"):
            evaluate_evidence(records)

    def test_rejects_oversized_approval_allowlist_before_digest_validation(self):
        digests = ["not-a-digest"] * 4097
        with self.assertRaisesRegex(EvidenceError, "at most 4096"):
            evaluate_evidence([], approved_evidence_digests=digests)

    def test_input_order_does_not_change_results(self):
        items = [evidence("handshake"), evidence("transport"),
                 evidence("framing"), evidence("serialization")]
        self.assertEqual(evaluate_approved(items),
                         evaluate_approved(list(reversed(items))))

    def test_mixed_artifacts_cannot_be_combined_implicitly(self):
        records = [
            evidence("transport", artifact_sha256="a" * 64),
            evidence("framing", artifact_sha256="a" * 64),
            evidence("serialization", artifact_sha256="b" * 64),
            evidence("handshake", artifact_sha256="b" * 64),
            evidence("login", artifact_sha256="b" * 64),
        ]
        with self.assertRaisesRegex(EvidenceError, "multiple artifacts"):
            evaluate_approved(records)

    def test_explicit_artifact_selection_keeps_prerequisites_isolated(self):
        records = [
            evidence("transport", artifact_sha256="a" * 64),
            evidence("framing", artifact_sha256="a" * 64),
            evidence("serialization", artifact_sha256="b" * 64),
            evidence("handshake", artifact_sha256="b" * 64),
            evidence("login", artifact_sha256="b" * 64),
        ]
        selected_a = {item.stage: item for item in evaluate_approved(
            records, artifact_sha256="a" * 64
        )}
        self.assertTrue(selected_a["transport"].ready)
        self.assertTrue(selected_a["framing"].ready)
        self.assertFalse(selected_a["serialization"].ready)
        self.assertFalse(selected_a["login"].ready)

        selected_b = {item.stage: item for item in evaluate_approved(
            records, artifact_sha256="b" * 64
        )}
        self.assertFalse(selected_b["transport"].ready)
        self.assertFalse(selected_b["framing"].ready)
        self.assertFalse(selected_b["serialization"].ready)
        self.assertFalse(selected_b["login"].ready)

    def test_explicit_artifact_selector_is_validated(self):
        records = [evidence("transport")]
        for digest in ("BAD", "A" * 64):
            with self.subTest(digest=digest), self.assertRaises(EvidenceError):
                evaluate_approved(records, artifact_sha256=digest)
        with self.assertRaisesRegex(EvidenceError, "no evidence records"):
            evaluate_approved(records, artifact_sha256="b" * 64)

    def test_static_offline_methods_never_unlock_protocol_stages(self):
        for method in ("apk_zip_inventory", "jadx_offline", "il2cpp_offline"):
            with self.subTest(method=method):
                records = [evidence(topic, method=method) for topic in STAGES]
                result = evaluate_approved(records)
                self.assertTrue(all(not item.ready for item in result))
                self.assertEqual(result[-1].missing, STAGES)

    def test_rejects_list_subclass_before_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom collection iterator must not run")

        with self.assertRaisesRegex(EvidenceError, "built-in list or tuple"):
            evaluate_evidence(HostileList())

    def test_rejects_evidence_subclass_before_field_access(self):
        class HostileEvidence(Evidence):
            def __post_init__(self):
                # Deliberately bypass base validation to exercise the gate.
                pass

            def __getattribute__(self, name):
                if name in {"topic", "artifact_sha256", "verified"}:
                    raise AssertionError("custom evidence accessor must not run")
                return super().__getattribute__(name)

        record = HostileEvidence(
            "transport", "a" * 64, "offline observation", "il2cpp_offline"
        )
        with self.assertRaisesRegex(EvidenceError, "exact Evidence"):
            evaluate_evidence([record])

    def test_artifact_selector_rejects_string_subclass(self):
        class Digest(str):
            pass

        with self.assertRaisesRegex(EvidenceError, "lowercase SHA-256"):
            evaluate_approved(
                [evidence("transport")], artifact_sha256=Digest("a" * 64)
            )


    def test_record_collection_is_snapshotted_before_topic_aggregation(self):
        records = [evidence(topic) for topic in STAGES[:5]]
        approved = tuple(evidence_record_digest(record) for record in records)
        original_digest = evidence_record_digest
        calls = 0

        def digest_and_mutate_records(record):
            nonlocal calls
            calls += 1
            if calls == 1:
                # Simulate another caller changing its list after fingerprint
                # selection but while the gate is aggregating approved records.
                records.clear()
            return original_digest(record)

        with patch(
            "server.protocol_evidence_gates.evidence_record_digest",
            side_effect=digest_and_mutate_records,
        ):
            result = evaluate_evidence(
                records,
                approved_evidence_digests=approved,
            )

        self.assertEqual(records, [])
        by_stage = {item.stage: item for item in result}
        self.assertTrue(by_stage["transport"].ready)
        self.assertTrue(by_stage["framing"].ready)
        self.assertTrue(by_stage["serialization"].ready)
        self.assertTrue(by_stage["handshake"].ready)
        self.assertTrue(by_stage["login"].ready)
        self.assertFalse(by_stage["session"].ready)

    def test_default_gate_requires_explicit_digest_approval(self):
        record = evidence("transport")
        self.assertFalse(evaluate_evidence([record])[0].ready)

        approved = (evidence_record_digest(record),)
        result = evaluate_evidence(
            [record], approved_evidence_digests=approved
        )
        self.assertTrue(result[0].ready)

        changed = Evidence(
            "transport",
            "a" * 64,
            "different observation",
            "authorized_local_test",
            True,
            "tests/test_protocol_evidence_gates.py",
            "python -m unittest discover -s tests -p test_protocol_evidence_gates.py -v",
        )
        self.assertFalse(
            evaluate_evidence(
                [changed], approved_evidence_digests=approved
            )[0].ready
        )

    def test_approved_digest_values_are_validated(self):
        record = evidence("transport")
        for invalid in ("A" * 64, "not-a-digest", True):
            with self.subTest(invalid=repr(invalid)), self.assertRaises(EvidenceError):
                evaluate_evidence(
                    [record], approved_evidence_digests=(invalid,)
                )
        digest = evidence_record_digest(record)
        with self.assertRaisesRegex(EvidenceError, "duplicate"):
            evaluate_evidence(
                [record], approved_evidence_digests=(digest, digest)
            )

    def test_rejects_frozen_record_mutated_before_gate_evaluation(self):
        record = evidence("transport")
        object.__setattr__(record, "verified", 1)

        with self.assertRaisesRegex(EvidenceError, "valid exact Evidence"):
            evaluate_evidence([record])

    def test_gate_uses_validated_record_copies_during_concurrent_mutation(self):
        records = [evidence(topic) for topic in STAGES[:4]]
        mutable_candidate = evidence("transport")
        records.append(mutable_candidate)
        approved = tuple(evidence_record_digest(record) for record in records)
        original_digest = evidence_record_digest
        digest_ready = threading.Event()
        resume_evaluation = threading.Event()
        digest_calls = 0
        results = []
        errors = []

        def pause_after_final_digest(record):
            nonlocal digest_calls
            digest_calls += 1
            digest = original_digest(record)
            if digest_calls == len(records):
                digest_ready.set()
                if not resume_evaluation.wait(timeout=2):
                    raise AssertionError("gate evaluation was not released")
            return digest

        def evaluate():
            try:
                with patch(
                    "server.protocol_evidence_gates.evidence_record_digest",
                    side_effect=pause_after_final_digest,
                ):
                    results.append(evaluate_evidence(
                        records,
                        approved_evidence_digests=approved,
                    ))
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=evaluate)
        worker.start()
        try:
            self.assertTrue(digest_ready.wait(timeout=2))
            # The digest was already computed for a second transport record.
            # Mutating its caller-owned object must not relabel it as login.
            object.__setattr__(mutable_candidate, "topic", "login")
        finally:
            resume_evaluation.set()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        by_stage = {item.stage: item for item in results[0]}
        self.assertTrue(by_stage["handshake"].ready)
        self.assertFalse(by_stage["login"].ready)
        self.assertEqual(by_stage["login"].missing, ("login",))


if __name__ == "__main__":
    unittest.main()
