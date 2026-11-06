"""Tests for evidence metadata validation, not AOW wire compatibility."""
import unittest

from server.offline_protocol_evidence import (
    EvidenceError, validate_record, validate_manifest,
)


def sample(**changes):
    record = {
        "id": "offline-test-001",
        "kind": "framing",
        "status": "unverified",
        "artifact_sha256": "a" * 64,
        "method": "Authorized local offline inspection",
        "reproduction": "Run isolated local fixture tests",
        "test_reference": "tests/test_offline_protocol_evidence.py",
        "notes": "Synthetic metadata only; no packet assertion",
    }
    record.update(changes)
    return record


class EvidenceManifestTests(unittest.TestCase):
    def test_accepts_synthetic_unverified_metadata(self):
        self.assertEqual(validate_record(sample())["status"], "unverified")

    def test_rejects_raw_capture_field(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(packet_bytes="deadbeef"))

    def test_rejects_invalid_hash(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(artifact_sha256="not-a-sha"))

    def test_rejects_unknown_kind(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(kind="invented_opcode"))

    def test_rejects_missing_reproduction_for_verified(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(status="verified", reproduction="pending"))

    def test_rejects_missing_test_for_verified(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(status="verified", test_reference="n/a"))

    def test_rejects_duplicate_identifiers(self):
        with self.assertRaises(EvidenceError):
            validate_manifest([sample(), sample(kind="login")])

    def test_rejects_control_characters(self):
        with self.assertRaises(EvidenceError):
            validate_record(sample(notes="unsafe\\nmetadata".replace("\\n", "\n")))

    def test_manifest_does_not_mutate_input(self):
        original = sample(notes="  local-only  ")
        result = validate_manifest([original])
        self.assertEqual(original["notes"], "  local-only  ")
        self.assertEqual(result[0]["notes"], "local-only")


if __name__ == "__main__":
    unittest.main()
