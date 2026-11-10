"""Synthetic ELF/metadata tests for native method evidence; no APK fixture."""
import json
import struct
import unittest

from tools.il2cpp_native_method_evidence import (
    _decode_aarch64_bl_target, _summarize_aarch64_calls, inspect_bytes,
)


def make_metadata(method_names, wrong_owner=False, *, image="ScriptsAssembly.dll",
                  type_name="Receiver", namespace="com.geargames.common.network"):
    header = bytearray(0x100)
    strings = bytearray()

    def add(value):
        index = len(strings)
        strings.extend(value.encode("utf-8") + b"\0")
        return index

    image_name = add(image)
    type_name_index = add(type_name)
    namespace_index = add(namespace)
    method_names = [add(name) for name in method_names]
    string_offset = len(header)
    method_offset = string_offset + len(strings)
    method_data = bytearray(len(method_names) * 0x24)
    for index, name_index in enumerate(method_names):
        struct.pack_into(
            "<Ii", method_data, index * 0x24, name_index,
            1 if wrong_owner else 0,
        )
    type_offset = method_offset + len(method_data)
    type_data = bytearray(0x58)
    struct.pack_into("<II", type_data, 0, type_name_index, namespace_index)
    struct.pack_into("<i", type_data, 0x24, 0)
    struct.pack_into("<H", type_data, 0x40, len(method_names))
    image_offset = type_offset + len(type_data)
    image_data = bytearray(0x28)
    struct.pack_into(
        "<10i", image_data, 0, image_name, 0, 0, 1, 0, 0, -1, 0, 0, 0
    )
    struct.pack_into("<II", header, 0, 0xFAB11BAF, 31)
    struct.pack_into("<II", header, 0x18, string_offset, len(strings))
    struct.pack_into("<II", header, 0x30, method_offset, len(method_data))
    struct.pack_into("<II", header, 0xA0, type_offset, len(type_data))
    struct.pack_into("<II", header, 0xA8, image_offset, len(image_data))
    return bytes(header) + bytes(strings) + bytes(method_data) + bytes(type_data) + bytes(image_data)


def make_elf(method_count, unrelocated=(), omit_table=False, target=0x5000,
             image="ScriptsAssembly.dll"):
    names = b"\0.shstrtab\0.rodata\0.data.rel.ro\0.text\0.rela.dyn\0"
    offsets = {
        name: names.index(name.encode())
        for name in (".shstrtab", ".rodata", ".data.rel.ro", ".text", ".rela.dyn")
    }
    image_name = image.encode("ascii") + b"\0"
    ro_off, relro_off, text_off, rela_off, names_off = 0x100, 0x120, 0x220, 0x240, 0x2A0
    names_end = names_off + len(names)
    shoff = (names_end + 7) & ~7
    elf = bytearray(shoff + 6 * 64)
    relro = bytearray(0x100)
    struct.pack_into("<I", relro, 8, method_count)
    pointer_table = 0x3040
    struct.pack_into("<Q", relro, 16, pointer_table)
    elf[ro_off:ro_off + len(image_name)] = image_name
    elf[relro_off:relro_off + len(relro)] = relro
    elf[text_off:text_off + 0x40] = b"\x1f\x20\x03\xd5" * 16
    elf[names_off:names_end] = names
    relocations = [(0x3000, (1 << 32) | 1027, 0x2000)]
    if not omit_table:
        relocations.append((0x3010, (1 << 32) | 1027, pointer_table))
    for index in range(method_count):
        if index not in unrelocated:
            relocations.append((
                pointer_table + index * 8, (1 << 32) | 1027,
                target + index * 4,
            ))
    rela_data = b"".join(struct.pack("<QQq", *item) for item in relocations)
    elf[rela_off:rela_off + len(rela_data)] = rela_data
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into(
        "<16sHHIQQQIHHHHHH", elf, 0, ident, 3, 183, 1, 0, 0, shoff, 0,
        64, 56, 0, 64, 6, 1,
    )

    def section(name, kind, flags, address, offset, size, alignment=8, entsize=0):
        return struct.pack(
            "<IIQQQQIIQQ", offsets[name], kind, flags, address, offset,
            size, 0, 0, alignment, entsize,
        )

    headers = [
        bytes(64),
        section(".shstrtab", 3, 0, 0, names_off, len(names), alignment=1),
        section(".rodata", 1, 2, 0x2000, ro_off, len(image_name), alignment=1),
        section(".data.rel.ro", 1, 3, 0x3000, relro_off, len(relro)),
        section(".text", 1, 6, 0x5000, text_off, 0x40, alignment=4),
        section(".rela.dyn", 4, 2, 0x6000, rela_off, len(rela_data), entsize=24),
    ]
    for index, item in enumerate(headers):
        start = shoff + index * 64
        elf[start:start + 64] = item
    return bytes(elf)


class NativeMethodEvidenceTests(unittest.TestCase):
    def test_maps_named_methods_to_executable_entries(self):
        report = inspect_bytes(
            make_metadata(["Cycle", "DoStreamReadedBytes"]), make_elf(2)
        )
        self.assertEqual(report["observed_network_methods"], 2)
        self.assertEqual(report["observed_login_session_serializers"], 0)
        self.assertEqual(report["observed_methods_total"], 2)
        self.assertEqual(report["executable_entrypoints"], 2)
        self.assertEqual(report["observed_serializer_helper_methods"], 0)
        self.assertEqual(report["serializer_callsite_summary"], [])
        self.assertEqual(report["methods"][0]["target_section"], ".text")
        self.assertEqual(
            [item["method"] for item in report["methods"]],
            ["Cycle", "DoStreamReadedBytes"],
        )

    def test_missing_relocation_is_not_guessed(self):
        report = inspect_bytes(
            make_metadata(["Cycle", "DoStreamReadedBytes"]),
            make_elf(2, unrelocated={1}),
        )
        status = {x["method"]: x["entry_status"] for x in report["methods"]}
        self.assertEqual(status["Cycle"], "executable_relocation")
        self.assertEqual(status["DoStreamReadedBytes"], "no_relative_relocation")

    def test_unresolved_module_is_not_accepted(self):
        report = inspect_bytes(
            make_metadata(["Cycle"]), make_elf(1, omit_table=True)
        )
        self.assertEqual(report["methods"][0]["entry_status"], "module_unresolved")

    def test_non_executable_target_is_not_accepted(self):
        report = inspect_bytes(
            make_metadata(["Cycle"]), make_elf(1, target=0x7000)
        )
        self.assertEqual(
            report["methods"][0]["entry_status"],
            "target_not_in_executable_section",
        )

    def test_method_owner_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            inspect_bytes(
                make_metadata(["Cycle"], wrong_owner=True), make_elf(1)
            )

    def test_unrelated_method_is_not_reported(self):
        report = inspect_bytes(
            make_metadata(["Cycle", "Unrelated"]), make_elf(2)
        )
        self.assertEqual(report["observed_network_methods"], 1)
        self.assertEqual(report["methods"][0]["method"], "Cycle")


    def test_maps_login_and_session_serializer_families(self):
        cases = (
            ("LoginRequestSTSerializer", "serialize"),
            ("LoginRequestSTDeserializer", "deserialize"),
            ("LoginAnswerSTSerializer", "serialize"),
            ("LoginAnswerSTDeserializer", "deserialize"),
            ("RegistrationRequestSTSerializer", "serialize"),
            ("RegistrationRequestSTDeserializer", "deserialize"),
            ("RegistrationAnswerSTSerializer", "serialize"),
            ("RegistrationAnswerSTDeserializer", "deserialize"),
            ("SessionRestoreRequestSTSerializer", "serialize"),
            ("SessionRestoreRequestSTDeserializer", "deserialize"),
            ("SessionRestoreAnswerSTSerializer", "serialize"),
            ("SessionRestoreAnswerSTDeserializer", "deserialize"),
            ("LoginToBattleRequestSTSerializer", "serialize"),
            ("LoginToBattleRequestSTDeserializer", "deserialize"),
            ("LoginToBattleAnswerSTSerializer", "serialize"),
            ("LoginToBattleAnswerSTDeserializer", "deserialize"),
            ("BattleSessionRestoreRequestSTSerializer", "serialize"),
            ("BattleSessionRestoreRequestSTDeserializer", "deserialize"),
            ("BattleSessionRestoreAnswerSTSerializer", "serialize"),
            ("BattleSessionRestoreAnswerSTDeserializer", "deserialize"),
        )
        for type_name, method_name in cases:
            with self.subTest(type_name=type_name):
                report = inspect_bytes(
                    make_metadata(
                        [method_name], image="ConvertedAssembly.dll",
                        type_name=type_name,
                        namespace="com.geargames.serialization.serializers",
                    ),
                    make_elf(1, image="ConvertedAssembly.dll"),
                )
                self.assertEqual(report["observed_network_methods"], 0)
                self.assertEqual(report["observed_login_session_serializers"], 1)
                self.assertEqual(report["observed_methods_total"], 1)
                self.assertEqual(report["executable_entrypoints"], 1)
                self.assertEqual(report["methods"][0]["category"], "login_session_serializer")
                self.assertEqual(report["methods"][0]["method"], method_name)


    @staticmethod
    def _encode_bl(pc, target):
        delta = target - pc
        if delta % 4:
            raise ValueError("unaligned branch target")
        immediate = delta // 4
        if not -(1 << 25) <= immediate < (1 << 25):
            raise ValueError("branch target outside AArch64 BL range")
        return 0x94000000 | (immediate & 0x03FFFFFF)

    def test_aarch64_bl_decoder_handles_forward_backward_and_non_bl(self):
        self.assertEqual(
            _decode_aarch64_bl_target(self._encode_bl(0x1000, 0x1010), 0x1000),
            0x1010,
        )
        self.assertEqual(
            _decode_aarch64_bl_target(self._encode_bl(0x1000, 0x0FF0), 0x1000),
            0x0FF0,
        )
        self.assertIsNone(_decode_aarch64_bl_target(0xD65F03C0, 0x1000))
        self.assertIsNone(_decode_aarch64_bl_target(0x94000000, 0x1002))

    def test_direct_serializer_helper_call_summary_is_redacted(self):
        start = 0x1000
        words = (
            self._encode_bl(start, 0x2000),
            self._encode_bl(start + 4, 0x1800),
            0xD63F0100,  # blr x8
            self._encode_bl(start + 12, 0x3000),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_aarch64_calls(
            code, start,
            {
                0x2000: ["com.geargames.serialization.SimpleSerializer::serializeInt"],
                0x3000: ["com.geargames.serialization.SimpleSerializer::serializeString"],
            },
        )
        self.assertEqual(
            summary["direct_helper_call_sequence"],
            [
                "com.geargames.serialization.SimpleSerializer::serializeInt",
                "com.geargames.serialization.SimpleSerializer::serializeString",
            ],
        )
        self.assertEqual(summary["direct_calls_not_in_helper_allowlist"], 1)
        self.assertEqual(summary["indirect_call_count"], 1)
        rendered = json.dumps(summary)
        self.assertNotIn("0x1000", rendered)
        self.assertNotIn("0x2000", rendered)
        self.assertNotIn("0x3000", rendered)

    def test_direct_call_summary_rejects_misaligned_windows(self):
        with self.assertRaises(ValueError):
            _summarize_aarch64_calls(bytes([0]), 0x1000, {})
        with self.assertRaises(ValueError):
            _summarize_aarch64_calls(bytes(4), 0x1002, {})

    def test_no_native_addresses_or_instructions_are_emitted(self):
        report = inspect_bytes(
            make_metadata(["Cycle"]), make_elf(1)
        )
        rendered = json.dumps(report)
        self.assertNotIn("0x3000", rendered)
        self.assertNotIn("0x5000", rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])


if __name__ == "__main__":
    unittest.main()
