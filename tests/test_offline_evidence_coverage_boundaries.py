"""Regression tests for metadata-only evidence coverage, not AOW protocol."""
import unittest

from server.offline_evidence_coverage import evidence_coverage
from server.offline_protocol_evidence import EvidenceError


def sample(**changes):
    item = {
        "id": "synthetic-001", "kind": "framing", "status": "unverified",
        "artifact_sha256": "a" * 64,
        "method": "Authorized local inspection",
        "reproduction": "Run isolated local fixture tests",
        "test_reference": "tests/test_offline_evidence_coverage_boundaries.py",
        "notes": "Synthetic metadata only",
    }
    item.update(changes)
    return item


class EvidenceCoverageBoundaryTests(unittest.TestCase):
    def test_empty_does_not_claim_verified_domains(self):
        result = evidence_coverage([])
        self.assertEqual(result["verified_domains"], [])
        self.assertEqual(result["verified_records"], 0)

    def test_unverified_does_not_claim_verified(self):
        result = evidence_coverage([sample()])
        self.assertEqual(result["domains"]["framing"]["unverified"], 1)
        self.assertEqual(result["verified_domains"], [])

    def test_verified_and_rejected_are_counted_separately(self):
        result = evidence_coverage([
            sample(id="one", status="verified", method="authorized_local_test"),
            sample(id="two", kind="login", status="rejected"),
        ])
        self.assertEqual(result["verified_domains"], ["framing"])
        self.assertEqual(result["domains"]["login"]["rejected"], 1)

    def test_summary_omits_identifiers_and_notes(self):
        result = evidence_coverage([sample(notes="SYNTHETIC_PRIVATE_MARKER")])
        self.assertNotIn("SYNTHETIC_PRIVATE_MARKER", repr(result))
        self.assertNotIn("a" * 64, repr(result))
        self.assertNotIn("synthetic-001", repr(result))

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(EvidenceError):
            evidence_coverage([sample(), sample(kind="login")])

    def test_unknown_payload_field_rejected(self):
        with self.assertRaises(EvidenceError):
            evidence_coverage([sample(packet_bytes="abcd")])

    def test_invalid_manifest_rejected(self):
        with self.assertRaises(EvidenceError):
            evidence_coverage("not a manifest")


if __name__ == "__main__":
    unittest.main()
