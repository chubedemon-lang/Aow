"""Synthetic resource-boundary tests for offline evidence manifests."""
import unittest
from unittest.mock import patch

from server.offline_protocol_evidence import (
    EvidenceError, MAX_MANIFEST_RECORDS, validate_manifest,
)
from server.offline_evidence_coverage import evidence_coverage


class EvidenceManifestLimitTests(unittest.TestCase):
    def test_empty_manifest_is_valid(self):
        self.assertEqual(validate_manifest([]), [])

    def test_oversized_manifest_rejected_before_record_validation(self):
        with patch("server.offline_protocol_evidence.validate_record") as validate:
            with self.assertRaisesRegex(EvidenceError, "maximum record count"):
                validate_manifest([None] * (MAX_MANIFEST_RECORDS + 1))
            validate.assert_not_called()

    def test_coverage_inherits_manifest_limit(self):
        with self.assertRaisesRegex(EvidenceError, "maximum record count"):
            evidence_coverage([None] * (MAX_MANIFEST_RECORDS + 1))

    def test_at_limit_still_validates_records(self):
        with self.assertRaisesRegex(EvidenceError, "approved metadata fields"):
            validate_manifest([None] * MAX_MANIFEST_RECORDS)


if __name__ == "__main__":
    unittest.main()
