"""Readiness gates require authorized local client evidence, not static facts alone."""
import unittest

from server.protocol_evidence_registry import Evidence, EvidenceError
from server.protocol_evidence_gates import STAGES, evaluate_evidence


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


class EvidenceGateTests(unittest.TestCase):
    def test_empty_registry_blocks_all_stages(self):
        result = evaluate_evidence([])
        self.assertEqual(len(result), len(STAGES))
        self.assertTrue(all(not item.ready for item in result))
        self.assertEqual(result[0].missing, ("transport",))

    def test_unverified_records_do_not_unlock(self):
        result = evaluate_evidence([evidence("transport", False)])
        self.assertFalse(result[0].ready)

    def test_verified_flag_without_reproduction_cannot_unlock(self):
        with self.assertRaises(EvidenceError):
            Evidence("transport", "a" * 64, "offline observation", "il2cpp_offline", True)

    def test_prerequisites_required(self):
        result = {item.stage: item for item in evaluate_evidence(
            [evidence("login"), evidence("framing")]
        )}
        self.assertFalse(result["login"].ready)
        self.assertEqual(result["login"].missing,
                         ("transport", "serialization", "handshake"))

    def test_verified_prefix_only(self):
        result = {item.stage: item for item in evaluate_evidence(
            [evidence("transport"), evidence("framing")]
        )}
        self.assertTrue(result["transport"].ready)
        self.assertTrue(result["framing"].ready)
        self.assertFalse(result["serialization"].ready)
        self.assertFalse(result["handshake"].ready)

    def test_handshake_requires_verified_primitive_serialization(self):
        topics = ("transport", "framing", "handshake")
        result = {item.stage: item for item in evaluate_evidence(
            [evidence(topic) for topic in topics]
        )}
        self.assertFalse(result["serialization"].ready)
        self.assertFalse(result["handshake"].ready)
        self.assertEqual(result["handshake"].missing, ("serialization",))

    def test_all_stages_need_individual_evidence(self):
        result = evaluate_evidence([evidence(topic) for topic in STAGES])
        self.assertTrue(all(item.ready for item in result))

    def test_player_and_map_are_required_before_movement(self):
        prefix = ("transport", "framing", "serialization", "handshake",
                  "login", "session", "movement")
        result = {item.stage: item for item in evaluate_evidence(
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

    def test_input_order_does_not_change_results(self):
        items = [evidence("handshake"), evidence("transport"),
                 evidence("framing"), evidence("serialization")]
        self.assertEqual(evaluate_evidence(items),
                         evaluate_evidence(list(reversed(items))))

    def test_mixed_artifacts_cannot_be_combined_implicitly(self):
        records = [
            evidence("transport", artifact_sha256="a" * 64),
            evidence("framing", artifact_sha256="a" * 64),
            evidence("serialization", artifact_sha256="b" * 64),
            evidence("handshake", artifact_sha256="b" * 64),
            evidence("login", artifact_sha256="b" * 64),
        ]
        with self.assertRaisesRegex(EvidenceError, "multiple artifacts"):
            evaluate_evidence(records)

    def test_explicit_artifact_selection_keeps_prerequisites_isolated(self):
        records = [
            evidence("transport", artifact_sha256="a" * 64),
            evidence("framing", artifact_sha256="a" * 64),
            evidence("serialization", artifact_sha256="b" * 64),
            evidence("handshake", artifact_sha256="b" * 64),
            evidence("login", artifact_sha256="b" * 64),
        ]
        selected_a = {item.stage: item for item in evaluate_evidence(
            records, artifact_sha256="a" * 64
        )}
        self.assertTrue(selected_a["transport"].ready)
        self.assertTrue(selected_a["framing"].ready)
        self.assertFalse(selected_a["serialization"].ready)
        self.assertFalse(selected_a["login"].ready)

        selected_b = {item.stage: item for item in evaluate_evidence(
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
                evaluate_evidence(records, artifact_sha256=digest)
        with self.assertRaisesRegex(EvidenceError, "no evidence records"):
            evaluate_evidence(records, artifact_sha256="b" * 64)

    def test_static_offline_methods_never_unlock_protocol_stages(self):
        for method in ("apk_zip_inventory", "jadx_offline", "il2cpp_offline"):
            with self.subTest(method=method):
                records = [evidence(topic, method=method) for topic in STAGES]
                result = evaluate_evidence(records)
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
            evaluate_evidence(
                [evidence("transport")], artifact_sha256=Digest("a" * 64)
            )


if __name__ == "__main__":
    unittest.main()
