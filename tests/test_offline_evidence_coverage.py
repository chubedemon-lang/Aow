"""Metadata coverage tests; all inputs are synthetic and unverified."""
import unittest

from server.offline_evidence_coverage import evidence_coverage
from server.offline_protocol_evidence import EvidenceError


def record(identifier, kind="framing", status="unverified"):
    return {
        "id": identifier,
        "kind": kind,
        "status": status,
        "artifact_sha256": "a" * 64,
        "method": (
            "authorized_local_test" if status == "verified"
            else "Authorized local synthetic test"
        ),
        "reproduction": "Run local synthetic unit tests",
        "test_reference": "tests/test_offline_evidence_coverage.py",
        "notes": "Synthetic placeholder only",
    }


class CoverageTests(unittest.TestCase):
    def test_empty_manifest_does_not_claim_verification(self):
        summary = evidence_coverage([])
        self.assertEqual(summary["verified_domains"], [])
        self.assertEqual(summary["verified_records"], 0)
        self.assertEqual(summary["total_records"], 0)
        self.assertIs(summary["compatibility_confirmed"], False)

    def test_unverified_is_not_counted_as_verified(self):
        summary = evidence_coverage([record("sample1")])
        self.assertEqual(summary["domains"]["framing"]["unverified"], 1)
        self.assertEqual(summary["verified_domains"], [])

    def test_rejected_is_not_counted_as_verified(self):
        summary = evidence_coverage([record("sample2", status="rejected")])
        self.assertEqual(summary["domains"]["framing"]["rejected"], 1)
        self.assertEqual(summary["verified_domains"], [])

    def test_verified_metadata_is_only_counted_not_interpreted(self):
        summary = evidence_coverage([record("sample3", status="verified")])
        self.assertEqual(summary["verified_domains"], ["framing"])
        self.assertEqual(summary["verified_records"], 1)
        self.assertIs(summary["compatibility_confirmed"], False)

    def test_mixed_statuses_never_claim_compatibility(self):
        entries = [
            record("verified-frame", kind="framing", status="verified"),
            record("verified-login", kind="login", status="verified"),
            record("pending", kind="login", status="unverified"),
            record("rejected-map", kind="map", status="rejected"),
        ]
        summary = evidence_coverage(entries)
        self.assertEqual(summary["total_records"], 4)
        self.assertEqual(summary["verified_records"], 2)
        self.assertEqual(summary["verified_domains"], ["framing", "login"])
        self.assertIs(summary["compatibility_confirmed"], False)

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(EvidenceError):
            evidence_coverage([record("dup"), record("dup", kind="login")])

    def test_unknown_fields_rejected_before_summary(self):
        entry = record("raw")
        entry["packet_bytes"] = "secret"
        with self.assertRaises(EvidenceError):
            evidence_coverage([entry])

    def test_does_not_mutate_input(self):
        entries = [record("safe")]
        original = [dict(entries[0])]
        evidence_coverage(entries)
        self.assertEqual(entries, original)


if __name__ == "__main__":
    unittest.main()
