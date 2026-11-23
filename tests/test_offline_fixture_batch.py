"""All samples are invented; no original APK or packet data is included."""
import hashlib
import unittest
from unittest.mock import patch

from server.offline_fixture_batch import validate_fixture_batch
from server.offline_packet_fixture import FixtureValidationError, validate_packet_fixture


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

    def test_batch_snapshots_membership_before_validating_payloads(self):
        records = [fixture(b"a"), fixture(b"bc")]
        expected_sources = {record["source_sha256"] for record in records}
        original_validate = validate_packet_fixture
        calls = []

        def clear_caller_list(record, **kwargs):
            if not calls:
                records.clear()
            calls.append(record)
            return original_validate(record, **kwargs)

        with patch(
            "server.offline_fixture_batch.validate_packet_fixture",
            side_effect=clear_caller_list,
        ):
            result = validate_fixture_batch(
                records, expected_source_sha256s=expected_sources
            )

        self.assertEqual(result["count"], 2)
        self.assertEqual(result["total_bytes"], 3)
        self.assertEqual(records, [])

    def test_batch_detaches_every_record_before_first_payload_validation(self):
        records = [fixture(b"a"), fixture(b"bc")]
        second_record = records[1]
        expected_sources = {record["source_sha256"] for record in records}
        original_validate = validate_packet_fixture
        calls = []

        def mutate_later_record(record, **kwargs):
            if not calls:
                second_record["payload_hex"] = "zz"
                second_record["payload_sha256"] = "0" * 64
            calls.append(record)
            return original_validate(record, **kwargs)

        with patch(
            "server.offline_fixture_batch.validate_packet_fixture",
            side_effect=mutate_later_record,
        ):
            result = validate_fixture_batch(
                records, expected_source_sha256s=expected_sources
            )

        self.assertEqual(result["count"], 2)
        self.assertEqual(result["total_bytes"], 3)
        self.assertEqual(
            result["payload_sha256"],
            (hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"bc").hexdigest()),
        )
        self.assertEqual(second_record["payload_hex"], "zz")

    def test_no_raw_bytes_in_summary(self):
        self.assertNotIn(b"private", repr(validate([fixture(b"private")])).encode())

    def test_duplicate_rejected(self):
        with self.assertRaises(FixtureValidationError):
            validate([fixture(b"x"), fixture(b"x")])

    def test_same_payload_different_source(self):
        self.assertEqual(validate([fixture(b"x", "a"), fixture(b"x", "b")])["count"], 2)

    def test_zero_byte_fixture_allowed_after_exact_budget_is_consumed(self):
        result = validate(
            [fixture(b"x", "a"), fixture(b"", "b")],
            max_total_bytes=1,
        )
        self.assertEqual(result["count"], 2)
        self.assertEqual(result["total_bytes"], 1)
        self.assertEqual(result["payload_sha256"][1], hashlib.sha256(b"").hexdigest())

    def test_zero_byte_fixture_digest_is_still_checked_at_exact_budget(self):
        empty = fixture(b"", "b")
        empty["payload_sha256"] = "0" * 64
        with self.assertRaisesRegex(FixtureValidationError, "digest mismatch"):
            validate([fixture(b"x", "a"), empty], max_total_bytes=1)

    def test_nonempty_fixture_rejected_after_exact_budget_is_consumed(self):
        with self.assertRaisesRegex(FixtureValidationError, "batch byte limit exceeded"):
            validate(
                [fixture(b"x", "a"), fixture(b"y", "b")],
                max_total_bytes=1,
            )

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


    def test_rejects_list_subclasses_before_iteration(self):
        class ExplosiveList(list):
            def __iter__(self):
                raise AssertionError("custom list iteration must not run")

        record = fixture(b"x")
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch(
                ExplosiveList([record]),
                expected_source_sha256s={record["source_sha256"]},
            )

    def test_rejects_set_subclasses_before_iteration(self):
        class ExplosiveSet(set):
            def __iter__(self):
                raise AssertionError("custom set iteration must not run")

        record = fixture(b"x")
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch(
                [record],
                expected_source_sha256s=ExplosiveSet({record["source_sha256"]}),
            )

    def test_rejects_dict_subclasses_before_access(self):
        class ExplosiveDict(dict):
            def get(self, key, default=None):
                raise AssertionError("custom dict access must not run")

        record = fixture(b"x")
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch(
                [ExplosiveDict(record)],
                expected_source_sha256s={record["source_sha256"]},
            )

    def test_rejects_tuple_subclasses(self):
        class DerivedTuple(tuple):
            pass

        record = fixture(b"x")
        with self.assertRaises(FixtureValidationError):
            validate_fixture_batch(
                DerivedTuple([record]),
                expected_source_sha256s={record["source_sha256"]},
            )


if __name__ == "__main__":
    unittest.main()
