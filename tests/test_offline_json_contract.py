"""Synthetic contract tests for metadata-only JSON ingestion.

No APK, packet captures, IP addresses or proprietary data are included.
"""
import json
import unittest

from server.offline_manifest_json import load_manifest_json
from server.offline_protocol_evidence import EvidenceError


def sample_record(status="unverified"):
    return {
        "id": "synthetic-login-01",
        "kind": "login",
        "status": status,
        "artifact_sha256": "a" * 64,
        "method": "isolated synthetic fixture",
        "reproduction": "python -m unittest",
        "test_reference": "tests/test_offline_json_contract.py",
        "notes": "Synthetic metadata only",
    }


class OfflineJsonContractTests(unittest.TestCase):
    def test_valid_unverified_record_round_trip(self):
        record = sample_record()
        result = load_manifest_json(json.dumps([record]).encode("utf-8"))
        self.assertEqual(result, [record])
        self.assertIsNot(result[0], record)

    def test_verified_requires_reproducible_reference(self):
        record = sample_record("verified")
        record["test_reference"] = "pending"
        with self.assertRaisesRegex(EvidenceError, "reproducible test reference"):
            load_manifest_json(json.dumps([record]).encode("utf-8"))

    def test_verified_requires_reproduction_instructions(self):
        record = sample_record("verified")
        record["reproduction"] = "unknown"
        with self.assertRaisesRegex(EvidenceError, "reproduction instructions"):
            load_manifest_json(json.dumps([record]).encode("utf-8"))

    def test_duplicate_evidence_identifiers_rejected(self):
        record = sample_record()
        with self.assertRaisesRegex(EvidenceError, "duplicate evidence id"):
            load_manifest_json(json.dumps([record, record]).encode("utf-8"))

    def test_raw_payload_field_rejected(self):
        record = sample_record()
        record["payload"] = "not-permitted"
        with self.assertRaisesRegex(EvidenceError, "approved metadata fields"):
            load_manifest_json(json.dumps([record]).encode("utf-8"))

    def test_valid_verified_record_does_not_imply_wire_compatibility(self):
        record = sample_record("verified")
        result = load_manifest_json(json.dumps([record]).encode("utf-8"))
        self.assertEqual(result[0]["status"], "verified")
        self.assertEqual(result[0]["kind"], "login")
        self.assertEqual(set(result[0]), set(record))


if __name__ == "__main__":
    unittest.main()
