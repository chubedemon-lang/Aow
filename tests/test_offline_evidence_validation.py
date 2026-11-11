"""Tests for metadata-only offline evidence validation."""
import unittest
from dataclasses import FrozenInstanceError

from server.offline_evidence_validation import EvidenceError, validate_record


class EvidenceValidationTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "kind": "apk", "sha256": "a" * 64,
            "source": "authorized local artifact",
            "observation": "hash computed locally",
            "verified": False,
        }

    def test_accepts_valid_metadata_without_claiming_protocol(self):
        result = validate_record(self.valid)
        self.assertEqual(result.sha256, "a" * 64)
        self.assertFalse(result.verified)
        with self.assertRaises(FrozenInstanceError):
            result.sha256 = "b" * 64

    def test_rejects_missing_and_extra_fields(self):
        for change in ({"source": None}, {"extra": "payload"}):
            record = dict(self.valid)
            record.update(change)
            with self.subTest(change=change), self.assertRaises(EvidenceError):
                validate_record(record)
        record = dict(self.valid)
        del record["source"]
        with self.assertRaises(EvidenceError):
            validate_record(record)

    def test_rejects_invalid_hash(self):
        for digest in ("A" * 64, "a" * 63, "g" * 64, 12, "a" * 65):
            with self.subTest(digest=digest), self.assertRaises(EvidenceError):
                validate_record({**self.valid, "sha256": digest})

    def test_rejects_unbounded_or_control_character_provenance(self):
        for source in ("", " ", "a" * 257, "local\nsecret"):
            with self.subTest(source=source):
                record = {**self.valid, "source": source, "verified": True}
                with self.assertRaises(EvidenceError):
                    validate_record(record)

    def test_rejects_unknown_kind_and_nonboolean_verified(self):
        for field, value in (("kind", "live_server"), ("verified", 1),
                             ("kind", None), ("verified", "yes")):
            with self.subTest(field=field, value=value):
                with self.assertRaises(EvidenceError):
                    validate_record({**self.valid, field: value})

    def test_rejects_sensitive_locations_and_credential_hints(self):
        examples = (
            "https://example.org/trace",
            "ftp://example.org/trace",
            "wss://example.org/socket",
            "www.example.org",
            "api.example.org:443",
            "192.168.1.20",
            "2001:db8::1",
            "[2001:db8::1]:443",
            "localhost:8080",
            "token=sample",
            "password: sample",
            "api_key=sample",
            "authorization: Bearer sample-value",
            "Bearer abcdefghijklmnop",
            "packet_bytes=deadbeef",
            "-----BEGIN PRIVATE KEY-----",
            "person@example.org",
            " trailing ",
        )
        for field in ("source", "observation"):
            for value in examples:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(EvidenceError):
                        validate_record({**self.valid, field: value})

    def test_accepts_sanitized_repository_local_references(self):
        for value in (
            "issue:2",
            "docs/PROTOCOL.md#framing",
            "tests/test_offline_evidence_validation.py",
        ):
            for field in ("source", "observation"):
                with self.subTest(field=field, value=value):
                    result = validate_record({**self.valid, field: value})
                    self.assertEqual(getattr(result, field), value)

    def test_rejects_whitespace_only_even_if_unverified(self):
        for field in ("source", "observation"):
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                validate_record({**self.valid, field: "   ", "verified": False})


if __name__ == "__main__":
    unittest.main()
