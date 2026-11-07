"""Tests use invented local bytes, not APK packets or proprietary captures."""
import hashlib
import unittest

from server.offline_packet_fixture import FixtureValidationError, validate_packet_fixture


def fixture(payload=b"\x01\x02"):
    return {
        "source_sha256": "a" * 64,
        "payload_hex": payload.hex(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "verified": True,
    }


class OfflinePacketFixtureTests(unittest.TestCase):
    def test_valid_fixture_returns_bytes(self):
        self.assertEqual(validate_packet_fixture(fixture()), b"\x01\x02")

    def test_rejects_unverified(self):
        record = fixture()
        record["verified"] = 1
        with self.assertRaises(FixtureValidationError):
            validate_packet_fixture(record)

    def test_rejects_digest_mismatch(self):
        record = fixture()
        record["payload_sha256"] = "b" * 64
        with self.assertRaises(FixtureValidationError):
            validate_packet_fixture(record)

    def test_rejects_extra_fields(self):
        record = fixture()
        record["endpoint"] = "private"
        with self.assertRaises(FixtureValidationError):
            validate_packet_fixture(record)

    def test_rejects_invalid_hex(self):
        for value in ("", "0", "zz", "00 11", "00\n"):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate_packet_fixture({**fixture(), "payload_hex": value})

    def test_rejects_oversized_before_decoding(self):
        with self.assertRaises(FixtureValidationError):
            validate_packet_fixture(fixture(b"abc"), max_bytes=2)

    def test_rejects_invalid_limits(self):
        for value in (True, 0, -1, 1048577, "12"):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate_packet_fixture(fixture(), max_bytes=value)

    def test_rejects_bad_source_hash(self):
        with self.assertRaises(FixtureValidationError):
            validate_packet_fixture({**fixture(), "source_sha256": "A" * 64})


if __name__ == "__main__":
    unittest.main()
