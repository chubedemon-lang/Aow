"""Synthetic tests for bounded offline metadata JSON ingestion."""
import json
import unittest

from server.offline_manifest_json import (
    MAX_MANIFEST_JSON_BYTES, load_manifest_json,
)
from server.offline_protocol_evidence import EvidenceError


class OfflineManifestJsonTests(unittest.TestCase):
    def test_empty_manifest(self):
        self.assertEqual(load_manifest_json(b"[]"), [])

    def test_wrong_type(self):
        with self.assertRaises(EvidenceError):
            load_manifest_json("[]")

    def test_invalid_utf8(self):
        with self.assertRaises(EvidenceError):
            load_manifest_json(b"\\xff")

    def test_invalid_json(self):
        with self.assertRaises(EvidenceError):
            load_manifest_json(b"[}")

    def test_duplicate_keys(self):
        with self.assertRaisesRegex(EvidenceError, "duplicate JSON object key"):
            load_manifest_json(b'[{"id":"a","id":"b"}]')

    def test_nested_duplicate_key_preserves_error(self):
        with self.assertRaisesRegex(EvidenceError, "duplicate JSON object key"):
            load_manifest_json(b'[{"metadata":{"kind":"a","kind":"b"}}]')

    def test_nonfinite_constant(self):
        with self.assertRaises(EvidenceError):
            load_manifest_json(b'[NaN]')

    def test_oversized_bytes_rejected(self):
        with self.assertRaisesRegex(EvidenceError, "byte limit"):
            load_manifest_json(b" " * (MAX_MANIFEST_JSON_BYTES + 1))

    def test_root_must_be_list(self):
        with self.assertRaises(EvidenceError):
            load_manifest_json(b"{}")

    def test_schema_enforced(self):
        with self.assertRaises(EvidenceError):
            load_manifest_json(json.dumps([{"payload": "private"}]).encode())

    def test_rejects_bytes_subclass_before_length_or_decode_hooks(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom __len__ must not run")

            def decode(self, *args, **kwargs):
                raise AssertionError("custom decode must not run")

        with self.assertRaisesRegex(EvidenceError, "exact built-in bytes"):
            load_manifest_json(HostileBytes(b"[]"))


if __name__ == "__main__":
    unittest.main()
