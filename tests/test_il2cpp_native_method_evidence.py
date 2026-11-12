"""Synthetic ELF/metadata tests for native method evidence; no APK fixture."""
import json
import struct
import unittest

from tools.il2cpp_native_method_evidence import (
    R_AARCH64_RELATIVE,
    _decode_aarch64_adr, _decode_aarch64_adrp, _decode_aarch64_add_imm64,
    _decode_aarch64_ldr_x_unsigned, _decode_aarch64_mov_x_register,
    _decode_aarch64_bl_target,
    _decode_aarch64_b_target, _decode_aarch64_conditional_branch,
    _summarize_aarch64_calls, _summarize_control_flow_serializer_helper_blocks,
    _summarize_relocated_indirect_calls,
    _summarize_ordered_serializer_helper_calls, inspect_bytes,
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
        self.assertEqual(report["primitive_helper_callsite_summary"], [])
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

    def test_aarch64_b_decoder_handles_forward_backward_and_non_b(self):
        self.assertEqual(
            _decode_aarch64_b_target(self._encode_bl(0x1000, 0x1010) - 0x80000000, 0x1000),
            0x1010,
        )
        self.assertEqual(
            _decode_aarch64_b_target(0x14000000 | ((-4) & 0x03FFFFFF), 0x1000),
            0x0FF0,
        )
        self.assertIsNone(_decode_aarch64_b_target(0xD65F03C0, 0x1000))

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
            0x14000000 | (((0x4000 - (start + 16)) // 4) & 0x03FFFFFF),
            0xD61F0120,  # br x9
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_aarch64_calls(
            code, start,
            {
                0x2000: ["com.geargames.serialization.SimpleSerializer::serializeInt"],
                0x3000: ["com.geargames.serialization.SimpleSerializer::serializeString"],
                0x4000: ["com.geargames.serialization.SimpleSerializer::serializeChar"],
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
        self.assertEqual(
            summary["direct_tail_helper_call_sequence"],
            ["com.geargames.serialization.SimpleSerializer::serializeChar"],
        )
        self.assertEqual(summary["indirect_call_count"], 1)
        self.assertEqual(summary["indirect_tail_call_count"], 1)
        rendered = json.dumps(summary)
        self.assertNotIn("0x1000", rendered)
        self.assertNotIn("0x2000", rendered)
        self.assertNotIn("0x3000", rendered)
        self.assertNotIn("0x4000", rendered)

    def test_direct_call_summary_rejects_misaligned_windows(self):
        with self.assertRaises(ValueError):
            _summarize_aarch64_calls(bytes([0]), 0x1000, {})
        with self.assertRaises(ValueError):
            _summarize_aarch64_calls(bytes(4), 0x1002, {})

    def test_serializer_direct_call_targets_resolve_to_metadata_method_names(self):
        elf = bytearray(make_elf(2, image="ConvertedAssembly.dll"))
        struct.pack_into(
            "<I", elf, 0x220, self._encode_bl(0x5000, 0x5004)
        )
        metadata = make_metadata(
            ["serialize", "deserialize"],
            image="ConvertedAssembly.dll",
            type_name="LoginRequestSTSerializer",
            namespace="com.geargames.serialization.serializers",
        )
        report = inspect_bytes(metadata, bytes(elf))
        summary = report["serializer_callsite_summary"][0]
        self.assertEqual(
            summary["resolved_direct_method_call_counts"],
            {
                "com.geargames.serialization.serializers."
                "LoginRequestSTSerializer::deserialize/p0": 1
            },
        )
        self.assertEqual(summary["unresolved_direct_method_call_count"], 0)
        rendered = json.dumps(summary)
        self.assertNotIn("0x5000", rendered)
        self.assertNotIn("0x5004", rendered)

    def test_no_native_addresses_or_instructions_are_emitted(self):
        report = inspect_bytes(
            make_metadata(["Cycle"]), make_elf(1)
        )
        rendered = json.dumps(report)
        self.assertNotIn("0x3000", rendered)
        self.assertNotIn("0x5000", rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])


    @staticmethod
    def _encode_adr(pc, target, register):
        delta = target - pc
        if not -(1 << 20) <= delta < (1 << 20):
            raise ValueError("ADR target outside signed 21-bit range")
        immediate = delta & 0x1FFFFF
        return (
            0x10000000
            | ((immediate & 0x3) << 29)
            | (((immediate >> 2) & 0x7FFFF) << 5)
            | register
        )

    @staticmethod
    def _encode_adrp(pc, target_page, register):
        delta_pages = ((target_page & ~0xFFF) - (pc & ~0xFFF)) >> 12
        immediate = delta_pages & 0x1FFFFF
        return (
            0x90000000
            | ((immediate & 0x3) << 29)
            | (((immediate >> 2) & 0x7FFFF) << 5)
            | register
        )

    @staticmethod
    def _encode_add_x(rd, rn, immediate, shift12=False):
        if not 0 <= immediate <= 0xFFF:
            raise ValueError("immediate outside 12-bit range")
        return (
            0x91000000
            | ((1 if shift12 else 0) << 22)
            | (immediate << 10)
            | (rn << 5)
            | rd
        )

    @staticmethod
    def _encode_ldr_x(rt, rn, byte_offset=0):
        if byte_offset < 0 or byte_offset % 8 or byte_offset // 8 > 0xFFF:
            raise ValueError("invalid LDR offset")
        return 0xF9400000 | ((byte_offset // 8) << 10) | (rn << 5) | rt

    @staticmethod
    def _encode_mov_x(rd, rn):
        return 0xAA0003E0 | (rn << 16) | rd

    @staticmethod
    def _encode_blr(rn):
        return 0xD63F0000 | (rn << 5)

    def test_aarch64_adr_decoder_handles_forward_backward_and_rejects_invalid(self):
        self.assertEqual(
            _decode_aarch64_adr(self._encode_adr(0x1000, 0x1804, 8), 0x1000),
            (8, 0x1804),
        )
        self.assertEqual(
            _decode_aarch64_adr(self._encode_adr(0x2000, 0x1FF0, 9), 0x2000),
            (9, 0x1FF0),
        )
        self.assertIsNone(_decode_aarch64_adr(0x90000008, 0x1000))
        self.assertIsNone(_decode_aarch64_adr(self._encode_adr(0x1000, 0x1004, 31), 0x1000))
        self.assertIsNone(_decode_aarch64_adr(0x10000008, 0x1002))

    def test_relocated_indirect_call_resolves_adr_ldr_blr_chain(self):
        start = 0x5000
        words = (
            self._encode_adr(start, 0x3000, 8),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3000: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(
            summary["resolved_indirect_method_call_counts"],
            {"Receiver::Cycle": 1},
        )
        self.assertEqual(summary["unresolved_indirect_call_count"], 0)

    def test_relocated_indirect_call_resolves_adrp_add_ldr_blr_chain(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start,
            {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["com.geargames.serialization.SimpleSerializer::serializeString"]},
        )
        self.assertEqual(
            summary["resolved_indirect_method_call_counts"],
            {"com.geargames.serialization.SimpleSerializer::serializeString": 1},
        )
        self.assertEqual(summary["unresolved_indirect_call_count"], 0)
        rendered = json.dumps(summary)
        self.assertNotIn("0x3080", rendered)
        self.assertNotIn("0x5010", rendered)

    def test_relocated_indirect_call_resolves_after_mov_x_copy(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_mov_x(10, 9),
            self._encode_blr(10),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(
            summary["resolved_indirect_method_call_counts"],
            {"Receiver::Cycle": 1},
        )
        self.assertEqual(
            summary["resolved_indirect_method_call_sequence"],
            ["Receiver::Cycle"],
        )

    def test_mov_x_from_untracked_register_is_not_guessed(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_mov_x(10, 11),
            self._encode_blr(10),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(summary["resolved_indirect_method_call_counts"], {})
        self.assertEqual(summary["unresolved_indirect_call_count"], 1)

    def test_mov_x_zero_register_semantics_do_not_invent_targets(self):
        start = 0x5000
        base = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
        )
        discard = b"".join(struct.pack("<I", word) for word in (
            *base, self._encode_mov_x(31, 9), self._encode_blr(9)
        ))
        resolved = _summarize_relocated_indirect_calls(
            discard, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(
            resolved["resolved_indirect_method_call_counts"],
            {"Receiver::Cycle": 1},
        )

        zero_source = b"".join(struct.pack("<I", word) for word in (
            *base, self._encode_mov_x(10, 31), self._encode_blr(10)
        ))
        unresolved = _summarize_relocated_indirect_calls(
            zero_source, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(unresolved["resolved_indirect_method_call_counts"], {})
        self.assertEqual(unresolved["unresolved_indirect_call_count"], 1)

    def test_shifted_orr_is_not_accepted_as_mov_x_alias(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_mov_x(10, 9) | (1 << 10),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(summary["resolved_indirect_method_call_counts"], {})
        self.assertEqual(summary["unresolved_indirect_call_count"], 1)
        self.assertIsNone(_decode_aarch64_mov_x_register(0x2A0003E0 | (9 << 16) | 10))

    def test_relocated_indirect_call_accepts_shifted_add_and_ldr_offset(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x4000, 10),
            self._encode_add_x(10, 10, 1, shift12=True),
            self._encode_ldr_x(11, 10, 0x20),
            self._encode_blr(11),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x5020: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(
            summary["resolved_indirect_method_call_counts"],
            {"Receiver::Cycle": 1},
        )

    def test_unrelocated_or_non_relative_pointer_stays_unresolved(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        for relocation in (None, (2, 0x5010)):
            with self.subTest(relocation=relocation):
                mapping = {} if relocation is None else {0x3080: relocation}
                summary = _summarize_relocated_indirect_calls(
                    code, start, mapping, {0x5010: ["Receiver::Cycle"]}
                )
                self.assertEqual(summary["resolved_indirect_method_call_counts"], {})
                self.assertEqual(summary["unresolved_indirect_call_count"], 1)

    def test_unknown_instruction_breaks_indirect_resolution_chain(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            0xD65F03C0,
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3000: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(summary["resolved_indirect_method_call_counts"], {})
        self.assertEqual(summary["unresolved_indirect_call_count"], 1)

    def test_ambiguous_indirect_target_is_not_assigned_a_method(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle", "Sender::Cycle"]},
        )
        self.assertEqual(summary["resolved_indirect_method_call_counts"], {})
        self.assertEqual(summary["ambiguous_indirect_call_count"], 1)
        self.assertEqual(summary["resolved_indirect_method_call_sequence"], [])
        self.assertEqual(summary["unresolved_indirect_call_count"], 0)

    def test_indirect_tail_branch_is_reported_separately(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            0xD61F0000 | (9 << 5),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start, {0x3080: (R_AARCH64_RELATIVE, 0x5010)},
            {0x5010: ["Receiver::Cycle"]},
        )
        self.assertEqual(
            summary["resolved_indirect_tail_method_call_counts"],
            {"Receiver::Cycle": 1},
        )
        self.assertEqual(summary["unresolved_indirect_tail_call_count"], 0)

    def test_indirect_call_summary_preserves_resolved_call_and_tail_order(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
            self._encode_adrp(start + 16, 0x4000, 10),
            self._encode_add_x(10, 10, 0x20),
            self._encode_ldr_x(11, 10),
            self._encode_blr(11),
            self._encode_adrp(start + 32, 0x4000, 12),
            self._encode_add_x(12, 12, 0x28),
            self._encode_ldr_x(13, 12),
            0xD61F0000 | (13 << 5),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_relocated_indirect_calls(
            code, start,
            {
                0x3080: (R_AARCH64_RELATIVE, 0x6010),
                0x4020: (R_AARCH64_RELATIVE, 0x6020),
                0x4028: (R_AARCH64_RELATIVE, 0x6030),
            },
            {
                0x6010: ["SimpleSerializer::serializeInt"],
                0x6020: ["SimpleSerializer::serializeString"],
                0x6030: ["SimpleSerializer::serializeChar"],
            },
        )
        self.assertEqual(
            summary["resolved_indirect_method_call_sequence"],
            [
                "SimpleSerializer::serializeInt",
                "SimpleSerializer::serializeString",
            ],
        )
        self.assertEqual(
            summary["resolved_indirect_tail_method_call_sequence"],
            ["SimpleSerializer::serializeChar"],
        )
        rendered = json.dumps(summary)
        for address in ("0x3080", "0x4020", "0x4028", "0x6010", "0x6020", "0x6030"):
            self.assertNotIn(address, rendered)

    def test_aarch64_indirect_instruction_decoders_reject_other_words(self):
        self.assertIsNone(_decode_aarch64_adrp(0xD503201F, 0x5000))
        self.assertIsNone(_decode_aarch64_add_imm64(0xD503201F))
        self.assertIsNone(_decode_aarch64_ldr_x_unsigned(0xD503201F))


    def test_ordered_helper_summary_interleaves_direct_indirect_and_tail_calls(self):
        start = 0x5000
        words = (
            self._encode_bl(start, 0x2000),
            self._encode_adrp(start + 4, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
            self._encode_bl(start + 20, 0x2020),
            self._encode_adrp(start + 24, 0x4000, 10),
            self._encode_add_x(10, 10, 0x28),
            self._encode_ldr_x(11, 10),
            0xD61F0000 | (11 << 5),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        helper_targets = {
            0x2000: ["SimpleSerializer::serializeInt"],
            0x6010: ["SimpleSerializer::serializeString"],
            0x2020: ["SimpleSerializer::serializeBoolean"],
            0x6020: ["SimpleSerializer::serializeChar"],
        }
        summary = _summarize_ordered_serializer_helper_calls(
            code,
            start,
            {
                0x3080: (R_AARCH64_RELATIVE, 0x6010),
                0x4028: (R_AARCH64_RELATIVE, 0x6020),
            },
            helper_targets,
        )
        self.assertEqual(
            summary["linear_helper_callsite_order"],
            [
                {"kind": "direct_call", "method": "SimpleSerializer::serializeInt"},
                {"kind": "indirect_call", "method": "SimpleSerializer::serializeString"},
                {"kind": "direct_call", "method": "SimpleSerializer::serializeBoolean"},
                {"kind": "indirect_tail_call", "method": "SimpleSerializer::serializeChar"},
            ],
        )
        self.assertEqual(
            summary["linear_helper_callsite_counts"],
            {
                "SimpleSerializer::serializeBoolean": 1,
                "SimpleSerializer::serializeChar": 1,
                "SimpleSerializer::serializeInt": 1,
                "SimpleSerializer::serializeString": 1,
            },
        )
        rendered = json.dumps(summary)
        for address in ("0x2000", "0x2020", "0x3080", "0x4028", "0x6010", "0x6020"):
            self.assertNotIn(address, rendered)

    def test_ordered_helper_summary_marks_unresolved_indirect_site_without_guessing(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_ordered_serializer_helper_calls(
            code, start, {}, {}
        )
        self.assertEqual(
            summary["linear_helper_callsite_order"],
            [{
                "kind": "indirect_call",
                "resolution": "not_resolved_as_serializer_helper",
            }],
        )
        self.assertEqual(
            summary["indirect_callsite_not_resolved_as_helper_count"], 1
        )
        self.assertEqual(summary["ambiguous_indirect_helper_callsite_count"], 0)



    @staticmethod
    def _encode_b(pc, target):
        delta = target - pc
        if delta % 4:
            raise ValueError("unaligned branch target")
        immediate = delta // 4
        if not -(1 << 25) <= immediate < (1 << 25):
            raise ValueError("branch target outside AArch64 B range")
        return 0x14000000 | (immediate & 0x03FFFFFF)

    @staticmethod
    def _encode_b_cond(pc, target, condition=0):
        delta = target - pc
        if delta % 4:
            raise ValueError("unaligned branch target")
        immediate = delta // 4
        if not -(1 << 18) <= immediate < (1 << 18):
            raise ValueError("branch target outside AArch64 B.cond range")
        return 0x54000000 | ((immediate & 0x7FFFF) << 5) | condition

    def test_conditional_branch_decoder_handles_b_cond_cbz_and_tbz(self):
        start = 0x5000
        self.assertEqual(
            _decode_aarch64_conditional_branch(
                self._encode_b_cond(start, start + 12), start
            ),
            ("b_cond", start + 12),
        )
        self.assertEqual(
            _decode_aarch64_conditional_branch(
                0x34000000 | (2 << 5), start
            ),
            ("cbz_cbnz", start + 8),
        )
        self.assertEqual(
            _decode_aarch64_conditional_branch(
                0x36000000 | (((-2) & 0x3FFF) << 5), start
            ),
            ("tbz_tbnz", start - 8),
        )
        self.assertIsNone(
            _decode_aarch64_conditional_branch(0xD65F03C0, start)
        )

    def test_control_flow_summary_separates_mutually_exclusive_serializer_paths(self):
        start = 0x5000
        words = (
            self._encode_b_cond(start, start + 12),
            self._encode_bl(start + 4, 0x2000),
            self._encode_b(start + 8, start + 16),
            self._encode_bl(start + 12, 0x2020),
            0xD65F03C0,  # ret
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code,
            start,
            {},
            {
                0x2000: ["SimpleSerializer::serializeInt"],
                0x2020: ["SimpleSerializer::serializeString"],
            },
        )
        blocks = summary["control_flow_basic_blocks"]
        self.assertEqual(summary["control_flow_block_count"], 4)
        self.assertEqual(blocks[0]["successors"], [1, 2])
        self.assertEqual(blocks[1]["successors"], [3])
        self.assertEqual(blocks[2]["successors"], [3])
        self.assertEqual(blocks[1]["helper_calls"], [{
            "instruction_index": 1,
            "kind": "direct_call",
            "method": "SimpleSerializer::serializeInt",
        }])
        self.assertEqual(blocks[2]["helper_calls"], [{
            "instruction_index": 3,
            "kind": "direct_call",
            "method": "SimpleSerializer::serializeString",
        }])
        self.assertTrue(all(block["reachable"] for block in blocks))
        self.assertEqual(summary["control_flow_conditional_branch_count"], 1)
        rendered = json.dumps(summary)
        for address in ("0x2000", "0x2020", "0x5000", "0x500c"):
            self.assertNotIn(address, rendered)

    def test_control_flow_summary_excludes_unreachable_helper_callsite_from_reachable_path(self):
        start = 0x6000
        words = (
            self._encode_b(start, start + 8),
            self._encode_bl(start + 4, 0x2000),
            self._encode_bl(start + 8, 0x2020),
            0xD65F03C0,  # ret
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code,
            start,
            {},
            {
                0x2000: ["SimpleSerializer::serializeInt"],
                0x2020: ["SimpleSerializer::serializeString"],
            },
        )
        blocks = summary["control_flow_basic_blocks"]
        self.assertEqual(summary["control_flow_block_count"], 4)
        self.assertFalse(blocks[1]["reachable"])
        self.assertEqual(blocks[1]["helper_calls"][0]["method"],
                         "SimpleSerializer::serializeInt")
        self.assertTrue(blocks[2]["reachable"])
        self.assertEqual(blocks[2]["helper_calls"][0]["method"],
                         "SimpleSerializer::serializeString")
        self.assertEqual(summary["control_flow_reachable_helper_callsite_count"], 1)
        self.assertEqual(summary["control_flow_unreachable_helper_callsite_count"], 1)

    def test_control_flow_conditional_external_edge_keeps_fallthrough_reachable(self):
        start = 0x7000
        words = (
            self._encode_b_cond(start, start + 0x1000),
            self._encode_bl(start + 4, 0x2000),
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {},
            {0x2000: ["SimpleSerializer::serializeInt"]},
        )
        self.assertEqual(summary["control_flow_external_branch_exit_count"], 1)
        self.assertTrue(summary["control_flow_basic_blocks"][1]["reachable"])
        self.assertEqual(
            summary["control_flow_basic_blocks"][1]["helper_calls"][0]["method"],
            "SimpleSerializer::serializeInt",
        )

    def test_control_flow_summary_marks_unresolved_indirect_tail_as_exit(self):
        start = 0x8000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            0xD61F0000 | (9 << 5),
            self._encode_bl(start + 16, 0x2000),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code,
            start,
            {0x3080: (R_AARCH64_RELATIVE, 0x6010)},
            {0x2000: ["SimpleSerializer::serializeInt"]},
        )
        blocks = summary["control_flow_basic_blocks"]
        self.assertEqual(blocks[0]["terminator"], "indirect_tail")
        self.assertFalse(blocks[1]["reachable"])
        self.assertEqual(summary["control_flow_reachable_helper_callsite_count"], 0)
        self.assertEqual(summary["control_flow_unreachable_helper_callsite_count"], 1)


if __name__ == "__main__":
    unittest.main()
