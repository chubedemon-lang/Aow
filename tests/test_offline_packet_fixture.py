"""Tests use invented local bytes, not APK packets or proprietary captures."""
import hashlib
import unittest

from server.offline_packet_fixture import FixtureValidationError, validate_packet_fixture


SOURCE_SHA256 = "a" * 64


def fixture(payload=b"\x01\x02"):
    return {
        "source_sha256": SOURCE_SHA256,
        "payload_hex": payload.hex(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "verified": True,
    }


def validate(record, *, expected_source_sha256=SOURCE_SHA256, max_bytes=65536):
    return validate_packet_fixture(
        record,
        expected_source_sha256=expected_source_sha256,
        max_bytes=max_bytes,
    )


class OfflinePacketFixtureTests(unittest.TestCase):
    def test_valid_fixture_returns_bytes_when_source_digest_matches(self):
        self.assertEqual(validate(fixture()), b"\x01\x02")

    def test_accepts_empty_payload_with_the_empty_sha256(self):
        record = fixture(b"")
        self.assertEqual(record["payload_hex"], "")
        self.assertEqual(
            record["payload_sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(validate(record, max_bytes=1), b"")

    def test_rejects_empty_payload_with_a_nonempty_payload_digest(self):
        record = fixture(b"")
        record["payload_sha256"] = hashlib.sha256(b"x").hexdigest()
        with self.assertRaisesRegex(FixtureValidationError, "digest mismatch"):
            validate(record)

    def test_expected_source_digest_is_required(self):
        with self.assertRaises(TypeError):
            validate_packet_fixture(fixture())

    def test_rejects_mismatched_source_digest(self):
        with self.assertRaisesRegex(FixtureValidationError, "does not match"):
            validate(fixture(), expected_source_sha256="b" * 64)

    def test_rejects_invalid_expected_source_digest(self):
        for value in ("A" * 64, "a" * 63, "g" * 64, None, 12):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate(fixture(), expected_source_sha256=value)

    def test_rejects_unverified(self):
        record = fixture()
        record["verified"] = 1
        with self.assertRaises(FixtureValidationError):
            validate(record)

    def test_rejects_digest_mismatch(self):
        record = fixture()
        record["payload_sha256"] = "b" * 64
        with self.assertRaises(FixtureValidationError):
            validate(record)

    def test_rejects_extra_fields(self):
        record = fixture()
        record["endpoint"] = "private"
        with self.assertRaises(FixtureValidationError):
            validate(record)

    def test_rejects_invalid_hex(self):
        for value in ("0", "zz", "00 11", "00\n"):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate({**fixture(), "payload_hex": value})

    def test_rejects_oversized_before_decoding(self):
        with self.assertRaises(FixtureValidationError):
            validate(fixture(b"abc"), max_bytes=2)

    def test_rejects_invalid_limits(self):
        for value in (True, 0, -1, 1048577, "12"):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate(fixture(), max_bytes=value)

    def test_rejects_bad_record_source_hash(self):
        with self.assertRaises(FixtureValidationError):
            validate({**fixture(), "source_sha256": "A" * 64})


if __name__ == "__main__":
    unittest.main()
