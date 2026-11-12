"""All samples are invented; no original APK or packet data is included."""
import hashlib
import unittest

from server.offline_fixture_batch import validate_fixture_batch
from server.offline_packet_fixture import FixtureValidationError


def fixture(payload, source="a"):
    return {
        "source_sha256": source * 64,
        "payload_hex": payload.hex(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "verified": True,
    }


def validate(records, **kwargs):
    # Test convenience only: production callers must obtain this set from a
    # trusted private artifact inventory, not derive it from fixture records.
    kwargs.setdefault(
        "expected_source_sha256s",
        {
            record["source_sha256"]
            for record in records
            if isinstance(record, dict) and "source_sha256" in record
        },
    )
    return validate_fixture_batch(records, **kwargs)


class BatchTests(unittest.TestCase):
    def test_summary(self):
        result = validate([fixture(b"a"), fixture(b"bc")])
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["total_bytes"], 3)
        self.assertEqual(result["payload_sha256"][0], hashlib.sha256(b"a").hexdigest())

    def test_no_raw_bytes_in_summary(self):
        self.assertNotIn(b"private", repr(validate([fixture(b"private")])).encode())

    def test_duplicate_rejected(self):
        with self.assertRaises(FixtureValidationError):
            validate([fixture(b"x"), fixture(b"x")])

    def test_same_payload_different_source(self):
        self.assertEqual(validate([fixture(b"x", "a"), fixture(b"x", "b")])["count"], 2)

    def test_rejects_source_not_in_independent_expected_set(self):
        with self.assertRaisesRegex(FixtureValidationError, "expected source set"):
            validate_fixture_batch(
                [fixture(b"x", "a")],
                expected_source_sha256s={"b" * 64},
            )

    def test_expected_source_set_is_required(self):
        with self.assertRaises(TypeError):
            validate_fixture_batch([fixture(b"x")])

    def test_rejects_invalid_expected_source_set(self):
        for value in (None, set(), "a" * 64, {"A" * 64}, {"g" * 64}):
            with self.subTest(value=repr(value)), self.assertRaises(FixtureValidationError):
                validate_fixture_batch(
                    [fixture(b"x")], expected_source_sha256s=value
                )

    def test_total_budget(self):
        with self.assertRaises(FixtureValidationError):
            validate([fixture(b"ab"), fixture(b"cd")], max_total_bytes=3)

    def test_bad_record_fails_closed(self):
        with self.assertRaises(FixtureValidationError):
            validate([fixture(b"a"), {**fixture(b"b"), "verified": False}])

    def test_invalid_count(self):
        for records in ([], {}, [fixture(b"x")] * 3):
            with self.subTest(records=type(records)), self.assertRaises(FixtureValidationError):
                validate(records, max_records=2)

    def test_invalid_limits(self):
        for value in (True, 0, -1, 1025, "3"):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate([fixture(b"x")], max_records=value)
        for value in (True, 0, 16777217):
            with self.subTest(value=value), self.assertRaises(FixtureValidationError):
                validate([fixture(b"x")], max_total_bytes=value)


if __name__ == "__main__":
    unittest.main()
