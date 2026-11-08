"""Regression tests for metadata-only evidence batch validation."""
import unittest

from server.offline_evidence_batch import MAX_RECORDS, validate_batch
from server.offline_evidence_validation import EvidenceError


def sample(index=0, verified=True, kind="apk"):
    return {
        "kind": kind,
        "sha256": f"{index:064x}",
        "source": "authorized offline artifact",
        "observation": "local metadata inventory",
        "verified": verified,
    }


class EvidenceBatchTests(unittest.TestCase):
    def test_valid_batch_is_immutable(self):
        records = validate_batch([sample(1), sample(2, kind="local_capture")])
        self.assertIsInstance(records, tuple)
        self.assertEqual(len(records), 2)

    def test_duplicate_identity_rejected(self):
        with self.assertRaises(EvidenceError):
            validate_batch([sample(1), sample(1)])

    def test_same_digest_distinct_kind_allowed(self):
        self.assertEqual(len(validate_batch([sample(1), sample(1, kind="test_observation")])), 2)

    def test_verified_gate(self):
        with self.assertRaises(EvidenceError):
            validate_batch([sample(1, verified=False)], require_verified=True)
        self.assertFalse(validate_batch([sample(1, verified=False)])[0].verified)

    def test_size_and_type_bounds(self):
        for value in ([], {}, "not records", [sample(i) for i in range(MAX_RECORDS + 1)]):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(EvidenceError):
                    validate_batch(value)
        with self.assertRaises(EvidenceError):
            validate_batch([sample(1)], require_verified=1)

    def test_invalid_member_is_rejected(self):
        with self.assertRaises(EvidenceError):
            validate_batch([sample(1), {"kind": "apk"}])


if __name__ == "__main__":
    unittest.main()
