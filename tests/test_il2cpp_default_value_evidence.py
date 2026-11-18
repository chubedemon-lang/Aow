"""Synthetic-only tests for IL2CPP v31 compressed default-value evidence."""
import hashlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools.il2cpp_codegen_inventory import (
    ARM64_IL2CPP_MEMBER,
    METADATA_MEMBER,
    R_AARCH64_RELATIVE,
)
from tools.il2cpp_default_value_evidence import (
    DefaultValueEvidenceError,
    _resolve_type_codes_from_tables,
    decode_compressed_signed_int32,
    inspect_apk,
    inspect_bytes,
)


def make_type_tables():
    elf = bytearray(0x500)
    sections = {
        ".data.rel.ro": {
            "type": 1, "flags": 3, "address": 0x1000,
            "offset": 0x100, "size": 0x100,
        },
        ".data": {
            "type": 1, "flags": 3, "address": 0x2000,
            "offset": 0x300, "size": 0x100,
        },
    }
    struct.pack_into("<Q", elf, 0x108, 4)
    type_codes = (0x08, 0x12, 0x15, 0x02)
    relocations = {0x1010: (R_AARCH64_RELATIVE, 0x1040)}
    targets = (0x2000, 0x2010, 0x2020, 0x2030)
    for index, (type_code, target) in enumerate(zip(type_codes, targets)):
        relocations[0x1040 + index * 8] = (R_AARCH64_RELATIVE, target)
        struct.pack_into("<I", elf, 0x300 + index * 16 + 8, type_code << 16)
    return bytes(elf), sections, relocations


def make_metadata():
    strings = bytearray()
    indexes = {}
    for value in (
        "com.geargames.common.network", "NetworkSettings",
        "HeaderLength", "ZipIntermediateBufferSize",
    ):
        indexes[value] = len(strings)
        strings.extend(value.encode() + b"\0")
    header_size = 0x100
    strings_offset = header_size
    methods_offset = strings_offset + len(strings)
    fields_offset = methods_offset
    field_blob = bytearray(24)
    struct.pack_into("<IiI", field_blob, 0, indexes["HeaderLength"], 0, 0x04000001)
    struct.pack_into(
        "<IiI", field_blob, 12,
        indexes["ZipIntermediateBufferSize"], 0, 0x04000002,
    )
    types_offset = fields_offset + len(field_blob)
    type_record = bytearray(0x58)
    struct.pack_into(
        "<II", type_record, 0,
        indexes["NetworkSettings"], indexes["com.geargames.common.network"],
    )
    struct.pack_into("<ii", type_record, 0x20, 0, 0)
    struct.pack_into("<HHH", type_record, 0x40, 0, 0, 2)
    defaults_offset = types_offset + len(type_record)
    defaults = struct.pack("<iiiiii", 0, 0, 0, 1, 0, 1)
    data_offset = defaults_offset + len(defaults)
    default_data = b"\x08\xa0\x00"
    header = bytearray(header_size)
    struct.pack_into("<II", header, 0, 0xFAB11BAF, 31)
    struct.pack_into("<II", header, 0x18, strings_offset, len(strings))
    struct.pack_into("<II", header, 0x30, methods_offset, 0)
    struct.pack_into("<II", header, 0x40, defaults_offset, len(defaults))
    struct.pack_into("<II", header, 0x48, data_offset, len(default_data))
    struct.pack_into("<II", header, 0x60, fields_offset, len(field_blob))
    struct.pack_into("<II", header, 0xA0, types_offset, len(type_record))
    return bytes(header + strings + field_blob + type_record + defaults + default_data)


def make_elf():
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


class CompressedSignedIntegerTests(unittest.TestCase):
    def test_decodes_one_two_and_four_byte_values(self):
        self.assertEqual(decode_compressed_signed_int32(b"\x08"), (4, 1))
        self.assertEqual(decode_compressed_signed_int32(b"\xa0\x00"), (4096, 2))
        self.assertEqual(
            decode_compressed_signed_int32(b"\xc0\x00\xea\x60"), (30000, 4)
        )

    def test_decodes_negative_zigzag_values(self):
        self.assertEqual(decode_compressed_signed_int32(b"\x01"), (-1, 1))
        self.assertEqual(decode_compressed_signed_int32(b"\x03"), (-2, 1))

    def test_rejects_truncated_encodings(self):
        for data in (b"\x80", b"\xc0\x00\x00"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode_compressed_signed_int32(data)

    def test_rejects_noncanonical_encodings(self):
        for data in (b"\x80\x01", b"\xc0\x00\x00\x01"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode_compressed_signed_int32(data)

    def test_rejects_invalid_prefix_and_offsets(self):
        for data, offset in (
            (b"\xe0\0\0\0", 0), (b"\x01", -1), (b"\x01", 1),
        ):
            with self.subTest(data=data, offset=offset), self.assertRaises(ValueError):
                decode_compressed_signed_int32(data, offset)

    def test_rejects_mutable_and_subclassed_bytes(self):
        class HostileBytes(bytes):
            pass
        for data in (bytearray(b"\x08"), HostileBytes(b"\x08")):
            with self.subTest(data_type=type(data)), self.assertRaises(ValueError):
                decode_compressed_signed_int32(data)


class NativeTypeTableTests(unittest.TestCase):
    def test_resolves_requested_indexes_from_unique_registration_table(self):
        elf, sections, relocations = make_type_tables()
        result, count = _resolve_type_codes_from_tables(
            elf, sections, relocations, [0, 3]
        )
        self.assertEqual(count, 4)
        self.assertEqual(result, {0: 0x08, 3: 0x02})

    def test_accepts_a_bounded_builtin_tuple_of_requested_indexes(self):
        elf, sections, relocations = make_type_tables()
        result, count = _resolve_type_codes_from_tables(
            elf, sections, relocations, (0, 3)
        )
        self.assertEqual(count, 4)
        self.assertEqual(result, {0: 0x08, 3: 0x02})

    def test_rejects_arbitrary_iterators_and_sequence_subclasses_before_iteration(self):
        class HostileIndexes(list):
            def __len__(self):
                raise AssertionError("custom length hook must not run")

            def __iter__(self):
                raise AssertionError("custom iterator hook must not run")

        elf, sections, relocations = make_type_tables()
        invalid_inputs = (iter((0, 3)), HostileIndexes([0, 3]))
        for indexes in invalid_inputs:
            with self.subTest(input_type=type(indexes).__name__):
                with self.assertRaisesRegex(
                    DefaultValueEvidenceError, "built-in list or tuple"
                ):
                    _resolve_type_codes_from_tables(
                        elf, sections, relocations, indexes
                    )

    def test_rejects_duplicate_and_over_limit_requested_indexes(self):
        elf, sections, relocations = make_type_tables()
        with self.assertRaisesRegex(DefaultValueEvidenceError, "duplicates"):
            _resolve_type_codes_from_tables(
                elf, sections, relocations, [0, 0]
            )

        with patch(
            "tools.il2cpp_default_value_evidence.MAX_REQUESTED_TYPE_INDEXES", 1
        ):
            with self.assertRaisesRegex(DefaultValueEvidenceError, "count"):
                _resolve_type_codes_from_tables(
                    elf, sections, relocations, [0, 3]
                )

    def test_rejects_registration_count_mismatch(self):
        elf, sections, relocations = make_type_tables()
        broken = bytearray(elf)
        struct.pack_into("<Q", broken, 0x108, 3)
        with self.assertRaises(DefaultValueEvidenceError):
            _resolve_type_codes_from_tables(
                bytes(broken), sections, relocations, [0, 3]
            )

    def test_rejects_missing_type_pointer_relocation(self):
        elf, sections, relocations = make_type_tables()
        del relocations[0x1048]
        with self.assertRaises(DefaultValueEvidenceError):
            _resolve_type_codes_from_tables(
                elf, sections, relocations, [0, 3]
            )

    def test_rejects_ambiguous_type_tables(self):
        elf, sections, relocations = make_type_tables()
        updated = bytearray(elf)
        struct.pack_into("<Q", updated, 0x118, 4)
        extra_start = 0x1080
        for index, target in enumerate((0x2000, 0x2010, 0x2020, 0x2030)):
            relocations[extra_start + index * 8] = (R_AARCH64_RELATIVE, target)
        relocations[0x1020] = (R_AARCH64_RELATIVE, extra_start)
        with self.assertRaises(DefaultValueEvidenceError):
            _resolve_type_codes_from_tables(
                bytes(updated), sections, relocations, [0, 3]
            )


class DefaultValueIntegrationTests(unittest.TestCase):
    def test_decodes_allowlisted_network_settings_defaults_after_native_type_resolution(self):
        report = inspect_bytes(make_metadata(), make_elf(), "a" * 64)
        fields = {item["name"]: item for item in report["fields"]}
        self.assertEqual(fields["HeaderLength"]["field_type"], "I4")
        self.assertEqual(fields["HeaderLength"]["default_type"], "I4")
        self.assertEqual(fields["HeaderLength"]["default_value"], 4)
        self.assertEqual(fields["ZipIntermediateBufferSize"]["default_value"], 4096)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_default_bytes_emitted"])

    def test_inspect_apk_reads_only_synthetic_metadata_and_arm64_members(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(METADATA_MEMBER, make_metadata())
                archive.writestr(ARM64_IL2CPP_MEMBER, make_elf())
                archive.writestr("assets/ignored.bundle", b"not extracted")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            report = inspect_apk(path, expected)
            self.assertEqual(report["apk_sha256"], expected)
            self.assertEqual(
                {item["name"]: item["default_value"] for item in report["fields"]},
                {"HeaderLength": 4, "ZipIntermediateBufferSize": 4096},
            )


if __name__ == "__main__":
    unittest.main()
