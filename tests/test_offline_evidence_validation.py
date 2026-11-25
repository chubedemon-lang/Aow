"""Tests for metadata-only offline evidence validation."""
import unittest
from dataclasses import FrozenInstanceError
from urllib.parse import quote

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

    def test_rejects_dict_subclass_before_mapping_hooks(self):
        class ExplosiveDict(dict):
            def __iter__(self):
                raise AssertionError("custom iteration hook must not run")

            def __getitem__(self, key):
                raise AssertionError("custom item hook must not run")

        with self.assertRaises(EvidenceError):
            validate_record(ExplosiveDict(self.valid))

    def test_rejects_string_subclass_keys_before_hash_or_equality_hooks(self):
        class GuardedKey(str):
            armed = False

            def __hash__(self):
                if self.armed:
                    raise AssertionError("custom hash hook must not run")
                return super().__hash__()

            def __eq__(self, other):
                if self.armed:
                    raise AssertionError("custom equality hook must not run")
                return super().__eq__(other)

        record = dict(self.valid)
        value = record.pop("kind")
        key = GuardedKey("kind")
        record[key] = value
        key.armed = True
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

    def test_rejects_absolute_private_file_paths(self):
        examples = (
            "/home/operator/captures/session.pcap",
            "/mnt/data/private/aow.apk",
            "~/private/capture.pcap",
            r"~\AppData\Local\capture.pcap",
            "//fileserver/private/capture.pcap",
            r"C:\Users\Operator\AppData\Local\capture.pcap",
            r"C:/Users/Operator/AppData/Local/capture.pcap",
            r"\\fileserver\private\capture.pcap",
            r"..\private\capture.pcap",
            r"docs\..\private\capture.pcap",
            r"\Users\Operator\AppData\Local\capture.pcap",
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
            "docs%2FPROTOCOL.md%23framing",
        ):
            for field in ("source", "observation"):
                with self.subTest(field=field, value=value):
                    result = validate_record({**self.valid, field: value})
                    self.assertEqual(getattr(result, field), value)

    def test_rejects_percent_encoded_sensitive_locations(self):
        examples = (
            "%2Fmnt%2Fdata%2Fprivate%2Faow.apk",
            "%2e%2e%2fprivate%2fcapture.pcap",
            "docs%5c..%5cprivate%5ccapture.pcap",
            "%252e%252e%255cprivate%255ccapture.pcap",
            "%25252e%25252e%25255cprivate%25255ccapture.pcap",
            "https%253A%252F%252Fexample.org%252Ftrace",
            "token%3Dsample-secret",
        )
        for field in ("source", "observation"):
            for value in examples:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(EvidenceError):
                        validate_record({**self.valid, field: value})

    def test_rejects_unicode_idn_hostnames(self):
        examples = (
            "例え.テスト",
            "сайт.рф",
            "service。例え。テスト",
        )
        for field in ("source", "observation"):
            for value in examples:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(EvidenceError):
                        validate_record({**self.valid, field: value})

    def test_accepts_unicode_prose_without_a_dotted_hostname(self):
        for value in ("phân tích APK ngoại tuyến", "đã kiểm tra dữ liệu cục bộ"):
            with self.subTest(value=value):
                self.assertEqual(validate_record({
                    **self.valid, "source": value
                }).source, value)

    def test_rejects_sensitive_values_with_escapes_remaining_after_decode_limit(self):
        examples = (
            "../private/capture.pcap",
            "token=sample-secret",
            "packet_bytes=deadbeef",
        )
        for value in examples:
            encoded = value
            for _ in range(4):
                encoded = quote(encoded, safe="")
            for field in ("source", "observation"):
                with self.subTest(field=field, value=value), self.assertRaises(EvidenceError):
                    validate_record({**self.valid, field: encoded})

    def test_rejects_whitespace_only_even_if_unverified(self):
        for field in ("source", "observation"):
            with self.subTest(field=field), self.assertRaises(EvidenceError):
                validate_record({**self.valid, field: "   ", "verified": False})


if __name__ == "__main__":
    unittest.main()
