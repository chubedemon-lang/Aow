"""Synthetic-only tests for the IL2CPP v31 FieldRef table inventory."""
import hashlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.il2cpp_field_ref_evidence import (
    FieldRefEvidenceError,
    correlate_field_info_usage_tokens,
    inspect_apk,
    inspect_metadata,
)
from tools.il2cpp_metadata_usage_evidence import (
    encode_field_info_usage_index,
    encode_method_def_usage_index,
)
from tools.il2cpp_metadata_inventory import METADATA_MEMBER


def make_metadata(field_refs=(), *, version=31, offset=0x100, size_delta=0):
    header = bytearray(0x100)
    struct.pack_into("<II", header, 0, 0xFAB11BAF, version)
    records = b"".join(struct.pack("<ii", *record) for record in field_refs)
    struct.pack_into(
        "<II", header, 0xB8, offset, len(records) + size_delta
    )
    return bytes(header) + records


class FieldRefEvidenceTests(unittest.TestCase):
    def test_reports_table_shape_and_selected_local_coordinates(self):
        metadata = make_metadata(((17, 0), (17, 2), (42, 5)))
        report = inspect_metadata(metadata, [2, 0])
        self.assertEqual(report["field_ref_count"], 3)
        self.assertEqual(report["unique_type_index_count"], 2)
        self.assertEqual(report["minimum_local_field_index"], 0)
        self.assertEqual(report["maximum_local_field_index"], 5)
        self.assertEqual(report["requested_field_refs"], [
            {
                "field_ref_index": 2,
                "type_index": 42,
                "field_index_within_type": 5,
            },
            {
                "field_ref_index": 0,
                "type_index": 17,
                "field_index_within_type": 0,
            },
        ])

    def test_empty_table_is_valid(self):
        report = inspect_metadata(make_metadata())
        self.assertEqual(report["field_ref_count"], 0)
        self.assertEqual(report["unique_type_index_count"], 0)
        self.assertIsNone(report["minimum_local_field_index"])
        self.assertEqual(report["requested_field_refs"], [])

    def test_rejects_unsupported_metadata_version(self):
        with self.assertRaisesRegex(FieldRefEvidenceError, "version 31"):
            inspect_metadata(make_metadata(((1, 0),), version=30))

    def test_rejects_partial_record_and_out_of_bounds_section(self):
        with self.assertRaisesRegex(FieldRefEvidenceError, "bounds or record"):
            inspect_metadata(make_metadata(((1, 0),), size_delta=1))
        broken = bytearray(make_metadata(((1, 0),)))
        struct.pack_into("<II", broken, 0xB8, len(broken) + 1, 8)
        with self.assertRaisesRegex(FieldRefEvidenceError, "bounds or record"):
            inspect_metadata(bytes(broken))

    def test_rejects_negative_type_or_local_field_index(self):
        for record in ((-1, 0), (1, -1)):
            with self.subTest(record=record):
                with self.assertRaises(FieldRefEvidenceError):
                    inspect_metadata(make_metadata((record,)))

    def test_rejects_invalid_requested_indexes(self):
        metadata = make_metadata(((1, 0), (2, 1)))
        for requested in ((True,), (-1,), (2,), (0, 0), iter((0,))):
            with self.subTest(requested=repr(requested)):
                with self.assertRaises(FieldRefEvidenceError):
                    inspect_metadata(metadata, requested)

    def test_rejects_list_subclasses_before_custom_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom iterator must not run")

        with self.assertRaisesRegex(FieldRefEvidenceError, "built-in list or tuple"):
            inspect_metadata(make_metadata(((1, 0),)), HostileList([0]))

    def test_rejects_mutable_or_non_bytes_metadata(self):
        for metadata in (bytearray(make_metadata()), memoryview(make_metadata())):
            with self.subTest(input_type=type(metadata).__name__):
                with self.assertRaisesRegex(FieldRefEvidenceError, "exact immutable bytes"):
                    inspect_metadata(metadata)

    def test_correlates_resolved_unresolved_and_out_of_range_usage_tokens(self):
        metadata = make_metadata(((17, 0), (17, 2), (42, 5)))
        tokens = [
            encode_field_info_usage_index(2, 31),
            encode_field_info_usage_index(0, 31),
            encode_field_info_usage_index(2, 31),
            encode_field_info_usage_index(3, 31),
            encode_method_def_usage_index(1, 31),
            0x80000002,  # FieldInfo usage type, but unresolved low-bit marker.
        ]
        report = correlate_field_info_usage_tokens(metadata, tokens)

        self.assertEqual(report["encoded_token_count"], 6)
        self.assertEqual(report["resolved_reference_count"], 3)
        self.assertEqual(report["unique_resolved_field_ref_count"], 2)
        self.assertEqual(report["unresolved_or_other_usage_type_count"], 2)
        self.assertEqual(report["out_of_range_field_info_index_count"], 1)
        self.assertFalse(report["no_out_of_range_resolved_indexes"])
        self.assertEqual(
            [entry["status"] for entry in report["references"]],
            [
                "field_ref_coordinate_resolved",
                "field_ref_coordinate_resolved",
                "field_ref_coordinate_resolved",
                "decoded_index_outside_field_ref_table",
                "unresolved_or_other_usage_type",
                "unresolved_or_other_usage_type",
            ],
        )
        self.assertEqual(report["references"][0]["type_index"], 42)
        self.assertEqual(report["references"][0]["field_index_within_type"], 5)
        self.assertEqual(report["references"][0]["field_ref_index"], 2)
        self.assertEqual(report["references"][2]["field_ref_index"], 2)
        self.assertNotIn("encoded_tokens", report)
        self.assertNotIn("encoded_token", report)

    def test_valid_token_correlation_preserves_occurrences_and_is_in_bounds(self):
        metadata = make_metadata(((17, 0), (42, 3)))
        token = encode_field_info_usage_index(1, 31)
        report = correlate_field_info_usage_tokens(metadata, [token, token])
        self.assertEqual(report["resolved_reference_count"], 2)
        self.assertEqual(report["unique_resolved_field_ref_count"], 1)
        self.assertTrue(report["no_out_of_range_resolved_indexes"])
        self.assertEqual(
            [entry["position"] for entry in report["references"]],
            [0, 1],
        )

    def test_rejects_hostile_or_invalid_field_info_token_collections(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom iterator must not run")

        metadata = make_metadata(((17, 0),))
        with self.assertRaisesRegex(FieldRefEvidenceError, "built-in list or tuple"):
            correlate_field_info_usage_tokens(metadata, HostileList([0]))
        for tokens in ((True,), (-1,), (1 << 32,)):
            with self.subTest(tokens=tokens), self.assertRaisesRegex(
                FieldRefEvidenceError, "unsigned 32-bit"
            ):
                correlate_field_info_usage_tokens(metadata, tokens)
        with self.assertRaisesRegex(FieldRefEvidenceError, "configured limit"):
            correlate_field_info_usage_tokens(metadata, [0] * 4097)

    def test_inspect_apk_uses_the_stable_metadata_reader(self):
        metadata = make_metadata(((17, 0), (42, 3)))
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(METADATA_MEMBER, metadata)
            expected_digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            expected_size = apk.stat().st_size
            token = encode_field_info_usage_index(1, 31)
            report = inspect_apk(apk, [1], [token])
        self.assertEqual(report["apk_sha256"], expected_digest)
        self.assertEqual(report["apk_size_bytes"], expected_size)
        self.assertEqual(report["field_ref_count"], 2)
        self.assertEqual(report["requested_field_refs"][0]["field_ref_index"], 1)
        self.assertEqual(
            report["field_info_usage_correlation"]["resolved_reference_count"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
