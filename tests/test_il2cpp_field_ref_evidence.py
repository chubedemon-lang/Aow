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
from tools.il2cpp_codegen_inventory import ARM64_IL2CPP_MEMBER, R_AARCH64_RELATIVE
from tools.il2cpp_metadata_inventory import METADATA_MEMBER


def make_metadata(field_refs=(), *, version=31, offset=0x100, size_delta=0):
    header = bytearray(0x100)
    struct.pack_into("<II", header, 0, 0xFAB11BAF, version)
    records = b"".join(struct.pack("<ii", *record) for record in field_refs)
    struct.pack_into(
        "<II", header, 0xB8, offset, len(records) + size_delta
    )
    return bytes(header) + records


def make_native_type_elf():
    """Build a tiny relocation-backed ARM64 IL2CPP type table."""
    names = b"\0.shstrtab\0.rodata\0.data.rel.ro\0.data\0.rela.dyn\0"
    name_offsets = {
        name: names.index(name.encode() + b"\0")
        for name in (".shstrtab", ".rodata", ".data.rel.ro", ".data", ".rela.dyn")
    }
    rodata_offset, relro_offset, data_offset = 0x100, 0x120, 0x220
    rela_offset, names_offset = 0x320, 0x400
    section_table_offset = (names_offset + len(names) + 7) & ~7
    elf = bytearray(section_table_offset + 6 * 64)
    elf[rodata_offset:rodata_offset + 1] = b"\0"
    relro = bytearray(0x100)
    struct.pack_into("<Q", relro, 8, 4)
    elf[relro_offset:relro_offset + len(relro)] = relro
    data = bytearray(0x100)
    for index, code in enumerate((0x08, 0x12, 0x15, 0x02)):
        struct.pack_into("<I", data, index * 16 + 8, code << 16)
    elf[data_offset:data_offset + len(data)] = data
    elf[names_offset:names_offset + len(names)] = names
    relocations = [
        (0x1010, (1 << 32) | R_AARCH64_RELATIVE, 0x1040),
    ]
    for index, target in enumerate((0x2000, 0x2010, 0x2020, 0x2030)):
        relocations.append((
            0x1040 + index * 8, (1 << 32) | R_AARCH64_RELATIVE, target,
        ))
    rela = b"".join(struct.pack("<QQq", *item) for item in relocations)
    elf[rela_offset:rela_offset + len(rela)] = rela
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", elf, 0,
        ident, 3, 183, 1, 0, 0, section_table_offset, 0,
        64, 56, 0, 64, 6, 1,
    )

    def section(name, kind, flags, address, offset, size, alignment=8, entry_size=0):
        return struct.pack(
            "<IIQQQQIIQQ", name_offsets[name], kind, flags, address,
            offset, size, 0, 0, alignment, entry_size,
        )

    headers = [
        bytes(64),
        section(".shstrtab", 3, 0, 0, names_offset, len(names), 1),
        section(".rodata", 1, 2, 0x5000, rodata_offset, 1, 1),
        section(".data.rel.ro", 1, 3, 0x1000, relro_offset, 0x100),
        section(".data", 1, 3, 0x2000, data_offset, 0x100),
        section(".rela.dyn", 4, 2, 0x3000, rela_offset, len(rela), 8, 24),
    ]
    for index, header in enumerate(headers):
        start = section_table_offset + index * 64
        elf[start:start + 64] = header
    return bytes(elf)


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


    def test_correlates_fieldref_type_indexes_to_native_registration_types(self):
        metadata = make_metadata(((0, 0), (1, 2), (2, 5)))
        tokens = [
            encode_field_info_usage_index(index, 31)
            for index in (0, 1, 2)
        ]
        report = correlate_field_info_usage_tokens(
            metadata, tokens, elf=make_native_type_elf()
        )
        self.assertEqual(
            report["native_type_resolution"],
            {
                "status": "resolved",
                "type_table_count": 4,
                "unique_type_index_count": 3,
            },
        )
        resolved = [
            item for item in report["references"]
            if item["status"] == "field_ref_coordinate_resolved"
        ]
        self.assertEqual(
            [item["native_type"]["type_name"] for item in resolved],
            ["I4", "CLASS", "GENERICINST"],
        )
        self.assertNotIn("native_addresses", report)
        self.assertNotIn("raw_bytes", report)

    def test_skips_native_resolution_when_no_fieldref_token_resolves(self):
        metadata = make_metadata(((17, 0),))
        tokens = [
            encode_method_def_usage_index(1, 31),
            encode_field_info_usage_index(3, 31),
        ]
        report = correlate_field_info_usage_tokens(
            metadata, tokens, elf=b"not an ELF"
        )
        self.assertEqual(
            report["native_type_resolution"],
            {
                "status": "no_resolved_field_refs",
                "type_table_count": None,
                "unique_type_index_count": 0,
            },
        )

    def test_rejects_mutable_or_subclassed_native_elf_before_parsing(self):
        class HostileBytes(bytes):
            pass

        metadata = make_metadata(((0, 0),))
        token = encode_field_info_usage_index(0, 31)
        for elf in (bytearray(make_native_type_elf()), HostileBytes(make_native_type_elf())):
            with self.subTest(elf_type=type(elf).__name__):
                with self.assertRaisesRegex(
                    FieldRefEvidenceError, "exact immutable bytes"
                ):
                    correlate_field_info_usage_tokens(metadata, [token], elf=elf)

    def test_fails_closed_when_native_type_table_cannot_be_resolved(self):
        metadata = make_metadata(((0, 0),))
        token = encode_field_info_usage_index(0, 31)
        with self.assertRaisesRegex(
            FieldRefEvidenceError, "native IL2CPP registration table"
        ):
            correlate_field_info_usage_tokens(metadata, [token], elf=b"not an ELF")

    def test_inspect_apk_can_resolve_fieldref_types_from_same_fingerprint(self):
        metadata = make_metadata(((0, 0), (1, 2)))
        elf = make_native_type_elf()
        token = encode_field_info_usage_index(1, 31)
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(METADATA_MEMBER, metadata)
                archive.writestr(ARM64_IL2CPP_MEMBER, elf)
            expected_digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            expected_size = apk.stat().st_size
            report = inspect_apk(
                apk, [1], [token], resolve_native_types=True
            )
        self.assertEqual(report["apk_sha256"], expected_digest)
        self.assertEqual(report["apk_size_bytes"], expected_size)
        correlation = report["field_info_usage_correlation"]
        self.assertEqual(correlation["native_type_resolution"]["status"], "resolved")
        self.assertEqual(
            correlation["references"][0]["native_type"]["type_name"], "CLASS"
        )

    def test_requires_fieldinfo_tokens_when_native_resolution_is_requested(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "unused.apk"
            apk.write_bytes(b"unused")
            with self.assertRaisesRegex(
                FieldRefEvidenceError, "requires FieldInfo usage tokens"
            ):
                inspect_apk(apk, resolve_native_types=True)


if __name__ == "__main__":
    unittest.main()
