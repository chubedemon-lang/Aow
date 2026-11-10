"""Synthetic ELF/metadata fixtures for the offline codegen inventory."""
import json
import os
import struct
import tempfile
import unittest
import zipfile

from tools.il2cpp_codegen_inventory import (
    ARM64_IL2CPP_MEMBER,
    METADATA_MEMBER,
    CodegenInventoryError,
    inspect_apk,
    inspect_bytes,
)


def make_metadata(method_count=2):
    header = bytearray(0x100)
    strings = b"TestAssembly.dll\0TestType\0Example\0"
    string_offset = len(header)
    method_offset = string_offset + len(strings)
    method_data = bytes(method_count * 0x24)
    type_offset = method_offset + len(method_data)
    type_data = bytearray(0x58)
    struct.pack_into("<II", type_data, 0, 17, 26)
    struct.pack_into("<i", type_data, 0x24, 0)
    struct.pack_into("<H", type_data, 0x40, method_count)
    image_offset = type_offset + len(type_data)
    image_data = bytearray(0x28)
    struct.pack_into("<10i", image_data, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 0)
    struct.pack_into("<II", header, 0, 0xFAB11BAF, 31)
    struct.pack_into("<II", header, 0x18, string_offset, len(strings))
    struct.pack_into("<II", header, 0x30, method_offset, len(method_data))
    struct.pack_into("<II", header, 0xA0, type_offset, len(type_data))
    struct.pack_into("<II", header, 0xA8, image_offset, len(image_data))
    return bytes(header) + strings + method_data + type_data + image_data


def make_elf(method_count=2, machine=183, pointer_target=0x5000):
    names = b"\0.shstrtab\0.rodata\0.data.rel.ro\0.text\0.rela.dyn\0"
    name_offsets = {
        ".shstrtab": names.index(b".shstrtab"),
        ".rodata": names.index(b".rodata"),
        ".data.rel.ro": names.index(b".data.rel.ro"),
        ".text": names.index(b".text"),
        ".rela.dyn": names.index(b".rela.dyn"),
    }
    image_name = b"TestAssembly.dll\0"
    rodata_offset, relro_offset = 0x100, 0x120
    text_offset, rela_offset, names_offset = 0x220, 0x240, 0x2A0
    names_end = names_offset + len(names)
    section_table_offset = (names_end + 7) & ~7
    elf = bytearray(section_table_offset + 6 * 64)
    relro = bytearray(0x100)
    struct.pack_into("<I", relro, 8, method_count)
    pointer_table = 0x3040
    struct.pack_into("<Q", relro, 16, pointer_table)
    elf[rodata_offset:rodata_offset + len(image_name)] = image_name
    elf[relro_offset:relro_offset + len(relro)] = relro
    elf[text_offset:text_offset + 0x20] = b"\x1f\x20\x03\xd5" * 8
    elf[names_offset:names_end] = names
    relocations = [
        (0x3000, (1 << 32) | 1027, 0x2000),
        (0x3010, (1 << 32) | 1027, pointer_table),
    ]
    for index in range(method_count):
        relocations.append((
            pointer_table + index * 8, (1 << 32) | 1027,
            pointer_target + index * 4,
        ))
    rela_data = b"".join(struct.pack("<QQq", *item) for item in relocations)
    elf[rela_offset:rela_offset + len(rela_data)] = rela_data
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", elf, 0,
        ident, 3, machine, 1, 0, 0, section_table_offset, 0,
        64, 56, 0, 64, 6, 1,
    )

    def section(name, kind, flags, address, offset, size, link=0,
                alignment=8, entry_size=0):
        return struct.pack(
            "<IIQQQQIIQQ", name_offsets[name], kind, flags, address,
            offset, size, link, 0, alignment, entry_size,
        )

    headers = [
        bytes(64),
        section(".shstrtab", 3, 0, 0, names_offset, len(names), alignment=1),
        section(".rodata", 1, 2, 0x2000, rodata_offset, len(image_name), alignment=1),
        section(".data.rel.ro", 1, 3, 0x3000, relro_offset, len(relro)),
        section(".text", 1, 6, 0x5000, text_offset, 0x20, alignment=4),
        section(".rela.dyn", 4, 2, 0x6000, rela_offset, len(rela_data),
                link=1, entry_size=24),
    ]
    for index, header in enumerate(headers):
        start = section_table_offset + index * 64
        elf[start:start + 64] = header
    return bytes(elf)


class CodegenInventoryTests(unittest.TestCase):
    def test_matches_image_and_native_pointer_table(self):
        report = inspect_bytes(make_metadata(), make_elf(), "a" * 64)
        self.assertEqual(report["metadata_version"], 31)
        self.assertEqual(report["metadata_image_count"], 1)
        self.assertEqual(report["metadata_method_definitions"], 2)
        self.assertEqual(report["matched_codegen_modules"], 1)
        self.assertEqual(report["unmatched_images"], [])
        self.assertEqual(report["mismatched_images"], [])
        self.assertEqual(report["method_pointer_slots"], 2)
        self.assertEqual(report["relocated_method_pointer_slots"], 2)
        self.assertEqual(report["relocated_targets_in_executable_sections"], 2)

    def test_report_does_not_emit_native_addresses(self):
        report = inspect_bytes(make_metadata(), make_elf())
        rendered = json.dumps(report)
        self.assertNotIn("0x3000", rendered)
        self.assertNotIn("0x5000", rendered)
        self.assertFalse(report["native_addresses_emitted"])

    def test_method_count_mismatch_is_reported(self):
        report = inspect_bytes(make_metadata(2), make_elf(1))
        self.assertEqual(report["matched_codegen_modules"], 0)
        self.assertEqual(report["unmatched_images"], [])
        self.assertEqual(report["mismatched_images"], [{
            "name": "TestAssembly.dll",
            "metadata_method_count": 2,
            "native_method_counts": [1],
        }])

    def test_non_executable_relocation_targets_are_not_counted(self):
        report = inspect_bytes(
            make_metadata(), make_elf(pointer_target=0x7000)
        )
        self.assertEqual(report["relocated_method_pointer_slots"], 2)
        self.assertEqual(report["relocated_targets_in_executable_sections"], 0)

    def test_rejects_wrong_architecture_and_truncated_elf(self):
        with self.assertRaises(CodegenInventoryError):
            inspect_bytes(make_metadata(), make_elf(machine=40))
        with self.assertRaises(CodegenInventoryError):
            inspect_bytes(make_metadata(), make_elf()[:80])

    def test_rejects_metadata_version_mismatch(self):
        metadata = bytearray(make_metadata())
        struct.pack_into("<I", metadata, 4, 30)
        with self.assertRaises(CodegenInventoryError):
            inspect_bytes(bytes(metadata), make_elf())

    def test_apk_reader_uses_only_required_members(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "authorized.apk")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(METADATA_MEMBER, make_metadata())
                archive.writestr(ARM64_IL2CPP_MEMBER, make_elf())
                archive.writestr("assets/ignored.bundle", b"not extracted")
            report = inspect_apk(path)
            self.assertEqual(len(report["apk_sha256"]), 64)
            self.assertEqual(report["matched_codegen_modules"], 1)

    def test_rejects_archive_missing_required_member(self):
        with tempfile.TemporaryDirectory() as temp:
            path = os.path.join(temp, "missing.apk")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(METADATA_MEMBER, make_metadata())
            with self.assertRaises(CodegenInventoryError):
                inspect_apk(path)


if __name__ == "__main__":
    unittest.main()
