"""Regression tests for private offline fixture batch boundaries; synthetic bytes only."""
import hashlib
import unittest

from server.offline_fixture_batch import validate_fixture_batch
from server.offline_packet_fixture import FixtureValidationError


def fixture(payload, source=b"synthetic source"):
    return {
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "payload_hex": payload.hex(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "verified": True,
    }


class OfflineFixturePrivacyBoundaryTests(unittest.TestCase):
    def test_summary_does_not_return_payload_or_hex(self):
        payload = b"PRIVATE_SYNTHETIC_PACKET_MARKER"
        summary = validate_fixture_batch([fixture(payload)])
        self.assertEqual(summary["total_bytes"], len(payload))
        self.assertEqual(summary["count"], 1)
        self.assertEqual(summary["payload_sha256"], (hashlib.sha256(payload).hexdigest(),))
        self.assertNotIn(payload.hex(), repr(summary))
        self.assertNotIn(payload.decode(), repr(summary))

    def test_reject_duplicate_same_source_and_payload(self):
        item = fixture(b"abc")
        with self.assertRaisesRegex(FixtureValidationError, "duplicate fixture"):
            validate_fixture_batch([item, dict(item)])

    def test_same_payload_from_distinct_sources_is_not_duplicate(self):
        summary = validate_fixture_batch([
            fixture(b"abc", b"source 1"), fixture(b"abc", b"source 2")
        ])
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["total_bytes"], 6)

    def test_exact_total_budget_and_one_byte_over(self):
        items = [fixture(b"ab"), fixture(b"c", b"source 2")]
        self.assertEqual(validate_fixture_batch(items, max_total_bytes=3)["total_bytes"], 3)
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch(items, max_total_bytes=2)

    def test_invalid_later_record_does_not_return_partial_summary(self):
        good = fixture(b"good")
        bad = fixture(b"bad", b"other")
        bad["payload_sha256"] = "0" * 64
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch([good, bad])

    def test_reject_boolean_limits(self):
        item = fixture(b"x")
        for kwargs in ({"max_records": True}, {"max_total_bytes": True},
                       {"max_records": False}, {"max_total_bytes": False}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(FixtureValidationError):
                    validate_fixture_batch([item], **kwargs)

    def test_reject_unverified_and_malformed_hex_without_leaking(self):
        item = fixture(b"secret")
        item["verified"] = False
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch([item])
        item["verified"] = True
        item["payload_hex"] = "secret_not_hex"
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch([item])


if __name__ == "__main__":
    unittest.main()
