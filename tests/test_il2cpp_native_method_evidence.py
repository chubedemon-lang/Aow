"""Synthetic ELF/metadata tests for native method evidence; no APK fixture."""
import json
import struct
import unittest

from tools.il2cpp_native_method_evidence import (
    MAX_ENTRYPOINT_WINDOW_BYTES, R_AARCH64_RELATIVE, _entrypoint_windows,
    _decode_aarch64_adr, _decode_aarch64_adrp, _decode_aarch64_add_imm64,
    _decode_aarch64_ldr_x_unsigned, _decode_aarch64_mov_x_register,
    _decode_aarch64_str_x_unsigned, _decode_aarch64_mov_w_register,
    _decode_aarch64_bl_target,
    _networksettings_first_non_default_field, _summarize_receiver_integer_lookup,
    _contains_hash_bucket_opcode_families,
    _summarize_bucketed_lookup_shape,
    _decode_aarch64_b_target, _decode_aarch64_conditional_branch,
    _decode_aarch64_conditional_branch_condition,
    _decode_aarch64_flag_setting_producer,
    _summarize_aarch64_calls, _summarize_control_flow_serializer_helper_blocks,
    _summarize_relocated_indirect_calls,
    _relocated_indirect_call_events,
    _summarize_ordered_serializer_helper_calls,
    _summarize_control_flow_helper_paths,
    _summarize_serializer_deserializer_path_alignment,
    _compare_login_session_serializer_paths, inspect_bytes,
)


def make_metadata(method_names, wrong_owner=False, *, image="ScriptsAssembly.dll",
                  type_name="Receiver", namespace="com.geargames.common.network",
                  fields=(), default_fields=()):
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
    field_name_indexes = [add(name) for name, _type_index, _token in fields]
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
    field_offset = type_offset + len(type_data)
    field_data = bytearray(len(fields) * 0x0C)
    for index, ((_name, type_index, token), name_index) in enumerate(
        zip(fields, field_name_indexes)
    ):
        struct.pack_into(
            "<IiI", field_data, index * 0x0C, name_index, type_index, token
        )
    default_offset = field_offset + len(field_data)
    default_data = bytearray(len(default_fields) * 0x0C)
    for index, field_index in enumerate(default_fields):
        struct.pack_into(
            "<iii", default_data, index * 0x0C, field_index, 0, 0
        )
    struct.pack_into("<i", type_data, 0x20, 0)
    struct.pack_into("<H", type_data, 0x44, len(fields))
    image_offset = default_offset + len(default_data)
    image_data = bytearray(0x28)
    struct.pack_into(
        "<10i", image_data, 0, image_name, 0, 0, 1, 0, 0, -1, 0, 0, 0
    )
    struct.pack_into("<II", header, 0, 0xFAB11BAF, 31)
    struct.pack_into("<II", header, 0x18, string_offset, len(strings))
    struct.pack_into("<II", header, 0x30, method_offset, len(method_data))
    struct.pack_into("<II", header, 0x40, default_offset, len(default_data))
    struct.pack_into("<II", header, 0x60, field_offset, len(field_data))
    struct.pack_into("<II", header, 0xA0, type_offset, len(type_data))
    struct.pack_into("<II", header, 0xA8, image_offset, len(image_data))
    return (bytes(header) + bytes(strings) + bytes(method_data) + bytes(type_data)
            + bytes(field_data) + bytes(default_data) + bytes(image_data))


def make_elf(
    method_count, unrelocated=(), omit_table=False, target=0x5000,
    image="ScriptsAssembly.dll", text_words=(), method_entry_targets=None,
    include_native_type_table=False, field_info_token=None,
):
    names = b"\0.shstrtab\0.rodata\0.data.rel.ro\0.text\0.rela.dyn\0"
    offsets = {
        name: names.index(name.encode())
        for name in (".shstrtab", ".rodata", ".data.rel.ro", ".text", ".rela.dyn")
    }
    image_name = image.encode("ascii") + b"\0"
    ro_off, relro_off, text_off, rela_off = 0x100, 0x120, 0x220, 0x280
    if len(text_words) > 16:
        raise ValueError("synthetic text window exceeds .text fixture")
    if method_entry_targets is None:
        method_entry_targets = tuple(
            target + index * 4 for index in range(method_count)
        )
    if type(include_native_type_table) is not bool:
        raise ValueError("include_native_type_table must be a built-in boolean")
    if (
        field_info_token is not None
        and (type(field_info_token) is not int or not 0 <= field_info_token <= 0xFFFFFFFF)
    ):
        raise ValueError("field_info_token must be an unsigned 32-bit integer")
    if (
        type(method_entry_targets) not in (tuple, list)
        or len(method_entry_targets) != method_count
        or any(
            type(item) is not int or item < 0 or item % 4
            for item in method_entry_targets
        )
    ):
        raise ValueError(
            "method entry targets must be aligned addresses matching method_count"
        )

    relro = bytearray(0x100)
    struct.pack_into("<I", relro, 8, method_count)
    pointer_table = 0x3040
    struct.pack_into("<Q", relro, 16, pointer_table)

    relocations = [(0x3000, (1 << 32) | 1027, 0x2000)]
    if field_info_token is not None:
        struct.pack_into("<Q", relro, 0x70, field_info_token)
        relocations.append((0x3068, (1 << 32) | 1027, 0x3070))
    if include_native_type_table:
        struct.pack_into("<Q", relro, 0x78, 4)
        struct.pack_into("<Q", relro, 0x80, 0x30A0)
        type_codes = (0x08, 0x12, 0x15, 0x02)
        for index, type_code in enumerate(type_codes):
            target_address = 0x30C0 + index * 0x10
            struct.pack_into("<Q", relro, 0xA0 + index * 8, target_address)
            struct.pack_into(
                "<I", relro, target_address - 0x3000 + 8, type_code << 16
            )
            relocations.append((
                0x30A0 + index * 8, (1 << 32) | 1027, target_address,
            ))
        relocations.append((0x3080, (1 << 32) | 1027, 0x30A0))
    if not omit_table:
        relocations.append((0x3010, (1 << 32) | 1027, pointer_table))
    for index, entry_target in enumerate(method_entry_targets):
        if index not in unrelocated:
            relocations.append((
                pointer_table + index * 8, (1 << 32) | 1027,
                entry_target,
            ))
    rela_data = b"".join(struct.pack("<QQq", *item) for item in relocations)

    # Keep every synthetic ELF file range disjoint. The previous fixture put
    # .rela.dyn at 0x240, inside the 0x220..0x260 .text range, silently
    # overwriting the final eight bytes of longer instruction vectors.
    names_off = (rela_off + len(rela_data) + 7) & ~7
    names_end = names_off + len(names)
    shoff = (names_end + 7) & ~7
    elf = bytearray(shoff + 6 * 64)

    elf[ro_off:ro_off + len(image_name)] = image_name
    elf[relro_off:relro_off + len(relro)] = relro
    elf[text_off:text_off + 0x40] = b"\x1f\x20\x03\xd5" * 16
    for index, word in enumerate(text_words):
        struct.pack_into("<I", elf, text_off + index * 4, word)
    elf[rela_off:rela_off + len(rela_data)] = rela_data
    elf[names_off:names_end] = names

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

    def test_message_helper_dictionary_roots_are_reported(self):
        method_names = (
            "EnsureLoadDictionary",
            "GetMessageTypeName",
            "GetMessageClassName",
        )
        report = inspect_bytes(
            make_metadata((*method_names, "Unrelated"), type_name="MessageHelper"),
            make_elf(len(method_names) + 1),
        )
        self.assertEqual(report["observed_network_methods"], len(method_names))
        observed = {
            (item["type"], item["method"])
            for item in report["network_callsite_summary"]
        }
        self.assertEqual(
            observed,
            {("MessageHelper", name) for name in method_names},
        )
        self.assertTrue(all(
            item["entry_window_bytes"] == 4
            for item in report["network_callsite_summary"]
        ))
        rendered = json.dumps(report["network_callsite_summary"])
        self.assertNotIn("0x5000", rendered)
        self.assertNotIn("0x5004", rendered)

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


    def test_network_field_summary_reports_allowlisted_names_and_default_presence(self):
        metadata = make_metadata(
            ["Cycle"],
            type_name="NetworkSettings",
            fields=(
                ("HeaderLength", 123, 0x04000001),
                # Unallowlisted fields are not interpreted by this report.
                ("UnrelatedField", -1, 0x04000002),
            ),
            default_fields=(0,),
        )
        report = inspect_bytes(metadata, make_elf(1))
        self.assertEqual(
            report["network_field_summary"],
            [{
                "namespace": "com.geargames.common.network",
                "type": "NetworkSettings",
                "field": "HeaderLength",
                "field_type_index": 123,
                "token": "0x4000001",
                "has_default_value": True,
            }],
        )
        rendered = json.dumps(report["network_field_summary"])
        self.assertIn("\"field_type_index\": 123", rendered)
        self.assertNotIn("default_value_bytes", rendered)
        self.assertNotIn("data_index", rendered)

    def test_network_field_summary_rejects_negative_allowlisted_type_index(self):
        metadata = make_metadata(
            ["Cycle"],
            type_name="NetworkSettings",
            fields=(("HeaderLength", -1, 0x04000001),),
        )
        with self.assertRaisesRegex(ValueError, "network field type index is negative"):
            inspect_bytes(metadata, make_elf(1))

    def test_message_helper_field_summary_names_both_dictionary_directions(self):
        metadata = make_metadata(
            ["InternalGetMessageType"],
            type_name="MessageHelper",
            fields=(
                ("m_messageTypeByMessageClass", 1, 0x04000001),
                ("m_messageClassByMessageType", 2, 0x04000002),
            ),
        )
        report = inspect_bytes(metadata, make_elf(1))
        self.assertEqual(
            [item["field"] for item in report["network_field_summary"]],
            [
                "m_messageClassByMessageType",
                "m_messageTypeByMessageClass",
            ],
        )
        self.assertEqual(
            [item["field_type_index"] for item in report["network_field_summary"]],
            [2, 1],
        )
        self.assertTrue(all(
            item["has_default_value"] is False
            for item in report["network_field_summary"]
        ))

    def test_network_field_summary_rejects_out_of_range_default_record(self):
        metadata = make_metadata(
            ["Cycle"],
            type_name="NetworkSettings",
            fields=(("HeaderLength", 123, 0x04000001),),
            default_fields=(4,),
        )
        with self.assertRaisesRegex(ValueError, "field default index"):
            inspect_bytes(metadata, make_elf(1))

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


    def test_relocated_indirect_events_reject_hostile_code_and_mapping_subclasses(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom byte length hook must not run")

        class HostileDict(dict):
            def get(self, *args, **kwargs):
                raise AssertionError("custom mapping lookup must not run")

        with self.assertRaisesRegex(ValueError, "exact built-in bytes"):
            _relocated_indirect_call_events(HostileBytes(b""), 0x5000, {})
        with self.assertRaisesRegex(ValueError, "exact built-in dict"):
            _relocated_indirect_call_events(b"", 0x5000, HostileDict())

    def test_relocated_indirect_events_reject_hostile_relocation_tuple(self):
        class HostileTuple(tuple):
            def __len__(self):
                raise AssertionError("custom tuple length hook must not run")

        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        with self.assertRaisesRegex(ValueError, "exact two-integer tuple"):
            _relocated_indirect_call_events(
                code,
                start,
                {0x3080: HostileTuple((R_AARCH64_RELATIVE, 0x6010))},
            )

    def test_control_flow_summary_rejects_hostile_container_subclasses(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom byte length hook must not run")

        class HostileDict(dict):
            def get(self, *args, **kwargs):
                raise AssertionError("custom mapping lookup must not run")

        with self.assertRaisesRegex(ValueError, "exact built-in bytes"):
            _summarize_control_flow_serializer_helper_blocks(
                HostileBytes(b""), 0x5000, {}, {}
            )
        with self.assertRaisesRegex(ValueError, "exact built-in dicts"):
            _summarize_control_flow_serializer_helper_blocks(
                b"", 0x5000, {}, HostileDict()
            )
        with self.assertRaisesRegex(ValueError, "exact built-in dicts"):
            _summarize_control_flow_serializer_helper_blocks(
                b"", 0x5000, HostileDict(), {}
            )
        with self.assertRaisesRegex(ValueError, "exact built-in dict"):
            _summarize_control_flow_serializer_helper_blocks(
                b"", 0x5000, {}, {}, method_targets=HostileDict()
            )

    def test_control_flow_summary_validates_target_map_keys_and_labels(self):
        class HostileLabels(list):
            def __len__(self):
                raise AssertionError("custom label length hook must not run")

        with self.assertRaisesRegex(ValueError, "helper target labels"):
            _summarize_control_flow_serializer_helper_blocks(
                b"", 0x5000, {}, {0x2000: HostileLabels(["SimpleSerializer::serializeInt"])}
            )
        with self.assertRaisesRegex(ValueError, "aligned built-in integers"):
            _summarize_control_flow_serializer_helper_blocks(
                b"", 0x5000, {}, {0x2001: ["SimpleSerializer::serializeInt"]}
            )
        with self.assertRaisesRegex(ValueError, "method target labels"):
            _summarize_control_flow_serializer_helper_blocks(
                b"", 0x5000, {}, {},
                method_targets={0x2000: [object()]},
            )

    def test_ordered_helper_summary_rejects_hostile_container_subclasses(self):
        class HostileDict(dict):
            def get(self, *args, **kwargs):
                raise AssertionError("custom mapping lookup must not run")

        class HostileLabels(list):
            def __len__(self):
                raise AssertionError("custom label length hook must not run")

        with self.assertRaisesRegex(ValueError, "exact built-in dicts"):
            _summarize_ordered_serializer_helper_calls(
                b"", 0x5000, {}, HostileDict()
            )
        with self.assertRaisesRegex(ValueError, "helper target labels"):
            _summarize_ordered_serializer_helper_calls(
                b"", 0x5000, {}, {0x2000: HostileLabels(["SimpleSerializer::serializeInt"])}
            )

    def test_ordered_helper_summary_rejects_unaligned_or_invalid_target_addresses(self):
        for target in (True, -4, 0x2001):
            with self.subTest(target=target):
                with self.assertRaisesRegex(
                    ValueError, "non-negative aligned built-in integers"
                ):
                    _summarize_ordered_serializer_helper_calls(
                        b"", 0x5000, {}, {target: ["SimpleSerializer::serializeInt"]}
                    )

    def test_ordered_helper_summary_rejects_empty_or_invalid_target_labels(self):
        for labels in ([], [""], [None]):
            with self.subTest(labels=labels):
                with self.assertRaisesRegex(
                    ValueError, "non-empty built-in string lists or tuples"
                ):
                    _summarize_ordered_serializer_helper_calls(
                        b"", 0x5000, {}, {0x2000: labels}
                    )

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

    def test_conditional_branch_predicate_decoder_preserves_encoded_operands(self):
        start = 0x5000
        self.assertEqual(
            _decode_aarch64_conditional_branch_condition(
                self._encode_b_cond(start, start + 12, condition=1)
            ),
            {
                "kind": "b_cond",
                "condition_code": 1,
                "condition_name": "ne",
            },
        )
        self.assertEqual(
            _decode_aarch64_conditional_branch_condition(
                0x34000000 | 2
            ),
            {
                "kind": "cbz_cbnz",
                "register_index": 2,
                "register_width_bits": 32,
                "predicate": "zero",
            },
        )
        self.assertEqual(
            _decode_aarch64_conditional_branch_condition(
                0xB5000000 | 3
            ),
            {
                "kind": "cbz_cbnz",
                "register_index": 3,
                "register_width_bits": 64,
                "predicate": "nonzero",
            },
        )
        self.assertEqual(
            _decode_aarch64_conditional_branch_condition(
                0xB6000000 | (5 << 19) | 5
            ),
            {
                "kind": "tbz_tbnz",
                "register_index": 5,
                "bit_index": 37,
                "predicate": "zero",
            },
        )
        self.assertEqual(
            _decode_aarch64_conditional_branch_condition(
                0x37000000 | (2 << 19) | 7
            ),
            {
                "kind": "tbz_tbnz",
                "register_index": 7,
                "bit_index": 2,
                "predicate": "nonzero",
            },
        )
        self.assertIsNone(_decode_aarch64_conditional_branch_condition(True))
        self.assertIsNone(_decode_aarch64_conditional_branch_condition(0xD65F03C0))


    def test_flag_setting_decoder_recognizes_cmp_and_cmn_aliases(self):
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xF1001C7F),
            {
                "kind": "cmp_immediate",
                "width_bits": 64,
                "source_register_index": 3,
                "source_register_31_role": "general_register",
                "destination_is_zero": True,
                "immediate_class": "nonzero_12bit",
            },
        )
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xB100043F),
            {
                "kind": "cmn_immediate",
                "width_bits": 64,
                "source_register_index": 1,
                "source_register_31_role": "general_register",
                "destination_is_zero": True,
                "immediate_class": "nonzero_12bit",
            },
        )
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xF10003FF),
            {
                "kind": "cmp_immediate",
                "width_bits": 64,
                "source_register_index": 31,
                "source_register_31_role": "stack_pointer",
                "destination_is_zero": True,
                "immediate_class": "zero",
            },
        )
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xF1001C60)["kind"],
            "subs_immediate",
        )
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xEB06089F),
            {
                "kind": "cmp_shifted_register",
                "width_bits": 64,
                "left_register_index": 4,
                "left_register_31_role": "general_register",
                "right_register_index": 6,
                "right_register_31_role": "general_register",
                "destination_is_zero": True,
                "shift_kind": "lsl",
                "shift_amount": 2,
            },
        )
        self.assertIsNone(_decode_aarch64_flag_setting_producer(0xD1001C7F))
        self.assertIsNone(_decode_aarch64_flag_setting_producer(True))
        self.assertIsNone(
            _decode_aarch64_flag_setting_producer(0xEB06089F | (3 << 22))
        )

    def test_shifted_register_flag_producer_models_register_31_as_zero_register(self):
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xEB060BFF),
            {
                "kind": "cmp_shifted_register",
                "width_bits": 64,
                "left_register_index": 31,
                "left_register_31_role": "zero_register",
                "right_register_index": 6,
                "right_register_31_role": "general_register",
                "destination_is_zero": True,
                "shift_kind": "lsl",
                "shift_amount": 2,
            },
        )
        self.assertEqual(
            _decode_aarch64_flag_setting_producer(0xEB1F089F)["right_register_31_role"],
            "zero_register",
        )
        # CMP SP, X6, LSL #2 uses the extended-register encoding, not this
        # shifted-register decoder; it must remain unresolved.
        self.assertIsNone(_decode_aarch64_flag_setting_producer(0xEB266BFF))

    def test_path_summary_rejects_stack_pointer_role_for_shifted_register_31(self):
        start = 0x5B00
        words = (
            0xEB060BFF,
            self._encode_b_cond(start + 4, start + 12, condition=0),
            0xD65F03C0,
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        branch_block = next(
            block for block in summary["control_flow_basic_blocks"]
            if block["terminator"] == "b_cond"
        )
        branch_block["terminator_flag_producer"]["left_register_31_role"] = "stack_pointer"
        with self.assertRaisesRegex(
            ValueError, "shifted-register flag producer operands are invalid"
        ):
            _summarize_control_flow_helper_paths(summary)

    def test_b_cond_path_carries_only_adjacent_nzcv_producer(self):
        start = 0x5600
        words = (
            0xF1001C7F,  # cmp x3, #7
            0xD503201F,  # nop
            self._encode_b_cond(start + 8, start + 16, condition=1),
            0xD65F03C0,
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        branch_block = next(
            block for block in summary["control_flow_basic_blocks"]
            if block["terminator"] == "b_cond"
        )
        expected = {
            "kind": "cmp_immediate",
            "width_bits": 64,
            "source_register_index": 3,
            "source_register_31_role": "general_register",
            "destination_is_zero": True,
            "immediate_class": "nonzero_12bit",
            "instruction_index": 0,
            "intervening_nop_count": 1,
        }
        self.assertEqual(branch_block["terminator_flag_producer"], expected)
        paths = _summarize_control_flow_helper_paths(summary)
        records = [
            item for path in paths["control_flow_paths"]
            for item in path["branch_conditions"]
        ]
        self.assertEqual(len(records), 2)
        self.assertTrue(all(item["flag_producer"] == expected for item in records))

    def test_b_cond_does_not_infer_flag_producer_across_non_nop_instruction(self):
        start = 0x5700
        words = (
            0xF1001C7F,  # cmp xzr, x3, #7
            0xAA0103E0,  # mov x0, x1; does not set NZCV
            self._encode_b_cond(start + 8, start + 16, condition=1),
            0xD65F03C0,
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        branch_block = next(
            block for block in summary["control_flow_basic_blocks"]
            if block["terminator"] == "b_cond"
        )
        self.assertNotIn("terminator_flag_producer", branch_block)
        paths = _summarize_control_flow_helper_paths(summary)
        records = [
            item for path in paths["control_flow_paths"]
            for item in path["branch_conditions"]
        ]
        self.assertTrue(all("flag_producer" not in item for item in records))

    def test_path_summary_rejects_non_adjacent_flag_producer_metadata(self):
        start = 0x5800
        words = (
            0xF1001C7F,
            self._encode_b_cond(start + 4, start + 12, condition=0),
            0xD65F03C0,
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        branch_block = next(
            block for block in summary["control_flow_basic_blocks"]
            if block["terminator"] == "b_cond"
        )
        branch_block["terminator_flag_producer"]["instruction_index"] = 0
        branch_block["terminator_flag_producer"]["intervening_nop_count"] = 1
        with self.assertRaisesRegex(ValueError, "not adjacent"):
            _summarize_control_flow_helper_paths(summary)


    def test_path_summary_rejects_malformed_flag_producer_width(self):
        start = 0x5900
        words = (
            0xF1001C7F,
            self._encode_b_cond(start + 4, start + 12, condition=0),
            0xD65F03C0,
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        branch_block = next(
            block for block in summary["control_flow_basic_blocks"]
            if block["terminator"] == "b_cond"
        )
        branch_block["terminator_flag_producer"]["width_bits"] = "64"
        with self.assertRaisesRegex(ValueError, "metadata is invalid"):
            _summarize_control_flow_helper_paths(summary)

    def test_path_summary_rejects_flag_producer_without_branch_predicate(self):
        start = 0x5A00
        words = (
            0xF1001C7F,
            self._encode_b_cond(start + 4, start + 12, condition=0),
            0xD65F03C0,
            0xD65F03C0,
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        branch_block = next(
            block for block in summary["control_flow_basic_blocks"]
            if block["terminator"] == "b_cond"
        )
        del branch_block["terminator_condition"]
        with self.assertRaisesRegex(ValueError, "require a ranged B.cond"):
            _summarize_control_flow_helper_paths(summary)

    def test_control_flow_paths_preserve_decoded_branch_predicates(self):
        start = 0x5200
        words = (
            self._encode_b_cond(start, start + 8, condition=1),
            self._encode_bl(start + 4, 0x2000),
            0xD65F03C0,  # ret
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {},
            {0x2000: ["SimpleSerializer::serializeInt"]},
        )
        self.assertEqual(summary["control_flow_instruction_count"], len(words))
        expected = {
            "kind": "b_cond",
            "condition_code": 1,
            "condition_name": "ne",
        }
        self.assertEqual(
            summary["control_flow_basic_blocks"][0]["terminator_condition"],
            expected,
        )
        paths = _summarize_control_flow_helper_paths(summary)
        records = [
            item
            for path in paths["control_flow_paths"]
            for item in path["branch_conditions"]
        ]
        self.assertEqual(len(records), 2)
        self.assertEqual(
            {item["outcome"] for item in records},
            {"taken", "fallthrough"},
        )
        self.assertTrue(all(item["condition"] == expected for item in records))
        self.assertEqual(
            {item["instruction_index"] for item in records},
            {0},
        )
        self.assertNotIn("0x5200", json.dumps(paths))


    def test_branch_condition_records_include_relative_terminator_index(self):
        start = 0x5400
        branch_words = (
            self._encode_b_cond(start, start + 8, condition=1),
            0xB4000000 | (2 << 5) | 3,  # cbz x3, +8
            0xB6000000 | (5 << 19) | (2 << 5) | 5,  # tbz x5, #37, +8
        )
        for branch_word in branch_words:
            with self.subTest(branch_word=hex(branch_word)):
                words = (branch_word, 0xD65F03C0, 0xD65F03C0)
                code = b"".join(struct.pack("<I", word) for word in words)
                summary = _summarize_control_flow_serializer_helper_blocks(
                    code, start, {}, {}
                )
                paths = _summarize_control_flow_helper_paths(summary)
                records = [
                    condition
                    for path in paths["control_flow_paths"]
                    for condition in path["branch_conditions"]
                ]
                self.assertEqual(len(records), 2)
                self.assertEqual(
                    {item["instruction_index"] for item in records},
                    {0},
                )
                self.assertTrue(all(
                    item["outcome"] in {"taken", "fallthrough"}
                    for item in records
                ))

    def test_terminal_conditional_branch_reports_out_of_window_fallthrough(self):
        start = 0x5300
        words = (
            0xD503201F,  # nop
            self._encode_b_cond(start + 4, start, condition=1),
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )
        block = summary["control_flow_basic_blocks"][0]
        self.assertEqual(block["successors"], [0])
        self.assertTrue(block["external_fallthrough_exit"])
        paths = _summarize_control_flow_helper_paths(summary)
        fallthrough = next(
            item for item in paths["control_flow_paths"]
            if item["exit_kind"] == "conditional_fallthrough_exit"
        )
        self.assertEqual(
            fallthrough["branch_conditions"],
            [{
                "from_block": 0,
                "to_block": None,
                "edge_kind": "conditional_fallthrough_exit",
                "outcome": "fallthrough",
                "condition": {
                    "kind": "b_cond",
                    "condition_code": 1,
                    "condition_name": "ne",
                },
                "instruction_index": 1,
            }],
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
        self.assertEqual(
            blocks[0]["successor_edges"],
            [
                {"target_block": 2, "kind": "conditional_taken"},
                {"target_block": 1, "kind": "conditional_fallthrough"},
            ],
        )
        self.assertEqual(blocks[1]["successors"], [3])
        self.assertEqual(
            blocks[1]["successor_edges"],
            [{"target_block": 3, "kind": "branch_target"}],
        )
        self.assertEqual(blocks[2]["successors"], [3])
        self.assertEqual(blocks[1]["callsite_observations"], [{
            "instruction_index": 1,
            "kind": "direct_call",
            "method": "SimpleSerializer::serializeInt",
        }])
        self.assertEqual(blocks[2]["callsite_observations"], [{
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
        self.assertEqual(summary["control_flow_block_count"], 3)
        self.assertFalse(blocks[1]["reachable"])
        self.assertEqual(blocks[1]["callsite_observations"][0]["method"],
                         "SimpleSerializer::serializeInt")
        self.assertTrue(blocks[2]["reachable"])
        self.assertEqual(blocks[2]["callsite_observations"][0]["method"],
                         "SimpleSerializer::serializeString")
        self.assertEqual(summary["control_flow_reachable_resolved_helper_callsite_count"], 1)
        self.assertEqual(summary["control_flow_unreachable_resolved_helper_callsite_count"], 1)
        self.assertEqual(summary["control_flow_unreachable_callsite_observation_count"], 1)

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
        self.assertTrue(summary["control_flow_basic_blocks"][0]["external_branch_exit"])
        self.assertTrue(summary["control_flow_basic_blocks"][1]["reachable"])
        self.assertEqual(
            summary["control_flow_basic_blocks"][1]["callsite_observations"][0]["method"],
            "SimpleSerializer::serializeInt",
        )

        paths = _summarize_control_flow_helper_paths(summary)
        self.assertEqual(
            [item["exit_kind"] for item in paths["control_flow_paths"]],
            ["conditional_branch_exit", "return"],
        )
        self.assertEqual(
            paths["control_flow_paths"][1]["helper_callsite_observations"][0]["method"],
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
        self.assertEqual(summary["control_flow_reachable_resolved_helper_callsite_count"], 0)
        self.assertEqual(summary["control_flow_unreachable_resolved_helper_callsite_count"], 1)
        self.assertEqual(summary["control_flow_reachable_callsite_observation_count"], 1)
        self.assertEqual(summary["control_flow_unreachable_callsite_observation_count"], 1)


    def test_control_flow_resolves_indirect_calls_on_unique_forward_paths(self):
        start = 0x5000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_b_cond(start + 4, start + 24),
            self._encode_add_x(8, 8, 0x80),
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
            0xD65F03C0,  # ret
            self._encode_ldr_x(10, 8),
            self._encode_blr(10),
            0xD65F03C0,  # ret
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code,
            start,
            {
                0x3080: (R_AARCH64_RELATIVE, 0x6010),
                0x3000: (R_AARCH64_RELATIVE, 0x6020),
            },
            {
                0x6010: ["SimpleSerializer::serializeInt"],
                0x6020: ["SimpleSerializer::serializeString"],
            },
        )

        blocks = summary["control_flow_basic_blocks"]
        self.assertEqual(summary["control_flow_block_count"], 3)
        self.assertEqual(blocks[0]["successors"], [1, 2])
        self.assertEqual(
            blocks[1]["callsite_observations"],
            [{
                "instruction_index": 4,
                "kind": "indirect_call",
                "method": "SimpleSerializer::serializeInt",
            }],
        )
        self.assertEqual(
            blocks[2]["callsite_observations"],
            [{
                "instruction_index": 7,
                "kind": "indirect_call",
                "method": "SimpleSerializer::serializeString",
            }],
        )
        self.assertEqual(
            summary["control_flow_reachable_resolved_helper_callsite_count"], 2
        )
        rendered = json.dumps(summary)
        for address in ("0x3000", "0x3080", "0x6010", "0x6020", "0x5000"):
            self.assertNotIn(address, rendered)

    def test_control_flow_drops_indirect_pointer_state_at_multi_predecessor_join(self):
        start = 0x7000
        words = (
            self._encode_adrp(start, 0x3000, 8),
            self._encode_b_cond(start + 4, start + 16),
            self._encode_add_x(8, 8, 0x80),
            self._encode_b(start + 12, start + 20),
            0xD503201F,  # nop on the other path
            self._encode_ldr_x(9, 8),
            self._encode_blr(9),
            0xD65F03C0,  # ret
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code,
            start,
            {0x3080: (R_AARCH64_RELATIVE, 0x6010)},
            {0x6010: ["SimpleSerializer::serializeInt"]},
        )

        blocks = summary["control_flow_basic_blocks"]
        self.assertEqual(blocks[3]["successors"], [])
        self.assertEqual(
            blocks[3]["callsite_observations"],
            [{
                "instruction_index": 6,
                "kind": "indirect_call",
                "resolution": "not_resolved_as_serializer_helper",
            }],
        )
        self.assertEqual(
            summary["control_flow_reachable_resolved_helper_callsite_count"], 0
        )


    def test_network_settings_initializers_are_callsite_roots(self):
        report = inspect_bytes(
            make_metadata(
                [".cctor", ".ctor"],
                type_name="NetworkSettings",
            ),
            make_elf(2),
        )
        summaries = {
            (item["type"], item["method"]): item
            for item in report["network_callsite_summary"]
        }
        self.assertEqual(
            set(summaries),
            {("NetworkSettings", ".cctor"), ("NetworkSettings", ".ctor")},
        )
        self.assertTrue(all(
            item["entry_window_kind"] == "next_distinct_executable_entry_in_section"
            for item in summaries.values()
        ))
        rendered = json.dumps(report)
        self.assertNotIn("0x5000", rendered)
        self.assertNotIn("0x5004", rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])

    def test_network_callsite_summary_resolves_only_metadata_backed_direct_calls(self):
        start = 0x5000
        report = inspect_bytes(
            make_metadata(["Cycle", "DoStreamReadedBytes"]),
            make_elf(
                2,
                text_words=(self._encode_bl(start, start + 4),),
            ),
        )
        self.assertEqual(len(report["network_callsite_summary"]), 1)
        summary = report["network_callsite_summary"][0]
        self.assertEqual(summary["type"], "Receiver")
        self.assertEqual(summary["method"], "Cycle")
        self.assertEqual(
            summary["resolved_direct_method_call_counts"],
            {"com.geargames.common.network.Receiver::DoStreamReadedBytes/p0": 1},
        )
        self.assertEqual(summary["unresolved_direct_method_call_count"], 0)
        rendered = json.dumps(report)
        self.assertNotIn("0x5000", rendered)
        self.assertNotIn("0x5004", rendered)


    def test_network_callsite_summary_preserves_branch_specific_metadata_method_targets(
        self,
    ):
        start = 0x5000
        words = (
            self._encode_b_cond(start, start + 20),
            self._encode_bl(start + 4, start + 0x30),
            self._encode_b(start + 8, start + 28),
            0xD503201F,  # unreachable fallthrough after unconditional branch
            0xD503201F,
            self._encode_bl(start + 20, start + 0x34),
            0xD65F03C0,  # ret
            0xD65F03C0,  # ret
        )
        report = inspect_bytes(
            make_metadata([
                "Cycle", "DoStreamReadedBytes", "GetHttpMessageResponse"
            ]),
            make_elf(
                3,
                text_words=words,
                method_entry_targets=(0x5000, 0x5030, 0x5034),
            ),
        )
        summary = next(
            item for item in report["network_callsite_summary"]
            if item["type"] == "Receiver" and item["method"] == "Cycle"
        )

        self.assertEqual(
            summary["control_flow_analysis_kind"],
            "bounded_intraprocedural_basic_blocks",
        )
        self.assertEqual(summary["control_flow_path_count"], 2)
        self.assertEqual(
            summary["control_flow_reachable_resolved_metadata_method_callsite_count"],
            2,
        )
        self.assertEqual(
            summary["control_flow_unreachable_resolved_metadata_method_callsite_count"],
            0,
        )
        path_methods = sorted(
            tuple(
                call["method"]
                for call in path["helper_callsite_observations"]
                if call.get("target_kind") == "metadata_method"
            )
            for path in summary["control_flow_paths"]
        )
        self.assertEqual(
            path_methods,
            sorted((
                ("com.geargames.common.network.Receiver::DoStreamReadedBytes/p0",),
                ("com.geargames.common.network.Receiver::GetHttpMessageResponse/p0",),
            )),
        )
        self.assertEqual(
            summary["resolved_direct_method_call_counts"],
            {
                "com.geargames.common.network.Receiver::DoStreamReadedBytes/p0": 1,
                "com.geargames.common.network.Receiver::GetHttpMessageResponse/p0": 1,
            },
        )
        rendered = json.dumps(summary)
        for address in ("0x5000", "0x5014", "0x5030", "0x5034"):
            self.assertNotIn(address, rendered)

    def test_network_and_login_serializer_summaries_include_redacted_memory_accesses(self):
        def encode_access(size, opc, base, target, immediate):
            return (
                (size << 30) | 0x39000000 | (opc << 22)
                | (immediate << 10) | (base << 5) | target
            )

        words = (
            encode_access(2, 0, 8, 9, 3),
            encode_access(2, 1, 8, 10, 3),
        )
        network = inspect_bytes(
            make_metadata(["Cycle"], type_name="Receiver"),
            make_elf(1, text_words=words),
        )
        network_summary = network["network_callsite_summary"][0]["memory_access_summary"]
        self.assertEqual(network_summary["memory_access_count"], 2)
        self.assertEqual(
            [item["operation"] for item in network_summary["memory_accesses"]],
            ["store", "load"],
        )
        self.assertEqual(
            [item["byte_offset"] for item in network_summary["memory_accesses"]],
            [12, 12],
        )

        serializer = inspect_bytes(
            make_metadata(
                ["serialize"],
                image="ConvertedAssembly.dll",
                type_name="LoginRequestSTSerializer",
                namespace="com.geargames.serialization.serializers",
            ),
            make_elf(1, image="ConvertedAssembly.dll", text_words=words),
        )
        serializer_summary = serializer["serializer_callsite_summary"][0]["memory_access_summary"]
        self.assertEqual(serializer_summary["memory_access_count"], 2)

        rendered = json.dumps({
            "network": network_summary,
            "serializer": serializer_summary,
        })
        self.assertNotIn("0x5000", rendered)
        self.assertNotIn("instruction_word", rendered)
        self.assertFalse(network_summary["native_addresses_emitted"])
        self.assertFalse(serializer_summary["raw_instructions_emitted"])


    def test_path_summary_validates_callsite_instruction_indexes_against_block_range(self):
        def summary(observations):
            return {
                "control_flow_block_count": 1,
                "control_flow_basic_blocks_truncated": False,
                "control_flow_basic_blocks": [{
                    "block_index": 0,
                    "instruction_start": 10,
                    "instruction_count": 2,
                    "successors": [],
                    "terminator": "return",
                    "callsite_observations": observations,
                }],
            }

        valid = _summarize_control_flow_helper_paths(summary([
            {
                "instruction_index": 10,
                "kind": "direct_call",
                "method": "SimpleSerializer::serializeInt",
            },
            {
                "instruction_index": 11,
                "kind": "direct_call",
                "method": "SimpleSerializer::serializeString",
            },
        ]))
        self.assertEqual(
            [
                item["instruction_index"]
                for item in valid["control_flow_paths"][0]["helper_callsite_observations"]
            ],
            [10, 11],
        )

        invalid_cases = (
            (
                [{"instruction_index": 12, "kind": "direct_call"}],
                "outside its block",
            ),
            (
                [
                    {"instruction_index": 11, "kind": "direct_call"},
                    {"instruction_index": 10, "kind": "direct_call"},
                ],
                "strictly increasing",
            ),
            (
                [
                    {"instruction_index": 10, "kind": "direct_call"},
                    {"instruction_index": 10, "kind": "direct_call"},
                ],
                "strictly increasing",
            ),
            (
                [
                    {"instruction_index": 10, "kind": "direct_call"},
                    {"kind": "direct_call"},
                ],
                "present on every observation",
            ),
            (
                [{"instruction_index": True, "kind": "direct_call"}],
                "non-negative integer",
            ),
        )
        for observations, message in invalid_cases:
            with self.subTest(observations=observations), self.assertRaisesRegex(
                ValueError, message
            ):
                _summarize_control_flow_helper_paths(summary(observations))

    def test_path_summary_accepts_legacy_callsite_observations_without_indexes(self):
        summary = {
            "control_flow_block_count": 1,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [{
                "block_index": 0,
                "successors": [],
                "terminator": "return",
                "callsite_observations": [
                    {"kind": "direct_call", "method": "SimpleSerializer::serializeInt"},
                ],
            }],
        }
        result = _summarize_control_flow_helper_paths(summary)
        self.assertEqual(result["control_flow_path_count"], 1)
        self.assertEqual(
            result["control_flow_paths"][0]["helper_callsite_observations"],
            [{
                "block_index": 0,
                "kind": "direct_call",
                "method": "SimpleSerializer::serializeInt",
            }],
        )


    def test_path_summary_rejects_instruction_range_outside_declared_window(self):
        summary = {
            "control_flow_instruction_count": 3,
            "control_flow_block_count": 1,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [{
                "block_index": 0,
                "instruction_start": 2,
                "instruction_count": 2,
                "successors": [],
                "terminator": "return",
                "callsite_observations": [],
            }],
        }
        with self.assertRaisesRegex(ValueError, "outside declared window"):
            _summarize_control_flow_helper_paths(summary)

    def test_path_summary_rejects_gapped_instruction_window_partition(self):
        summary = {
            "control_flow_instruction_count": 3,
            "control_flow_block_count": 2,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {
                    "block_index": 0,
                    "instruction_start": 0,
                    "instruction_count": 1,
                    "successors": [1],
                    "successor_edges": [
                        {"target_block": 1, "kind": "branch_target"},
                    ],
                    "terminator": "b",
                    "external_branch_exit": False,
                    "external_fallthrough_exit": False,
                    "callsite_observations": [],
                },
                {
                    "block_index": 1,
                    "instruction_start": 2,
                    "instruction_count": 1,
                    "successors": [],
                    "successor_edges": [],
                    "terminator": "return",
                    "external_branch_exit": False,
                    "external_fallthrough_exit": False,
                    "callsite_observations": [],
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "contiguous and non-overlapping"):
            _summarize_control_flow_helper_paths(summary)

    def test_path_summary_requires_ranges_for_declared_instruction_window(self):
        summary = {
            "control_flow_instruction_count": 1,
            "control_flow_block_count": 1,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [{
                "block_index": 0,
                "successors": [],
                "terminator": "return",
                "callsite_observations": [],
            }],
        }
        with self.assertRaisesRegex(ValueError, "require instruction ranges"):
            _summarize_control_flow_helper_paths(summary)

    def test_path_summary_rejects_conditional_edges_without_predicate(self):
        summary = {
            "control_flow_block_count": 2,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {
                    "block_index": 0,
                    "successors": [1],
                    "successor_edges": [
                        {"target_block": 1, "kind": "conditional_taken"},
                    ],
                    "terminator": "b_cond",
                    "callsite_observations": [],
                },
                {
                    "block_index": 1,
                    "successors": [],
                    "successor_edges": [],
                    "terminator": "return",
                    "callsite_observations": [],
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "require a matching branch predicate"):
            _summarize_control_flow_helper_paths(summary)

    def test_path_summary_validates_declared_cfg_edge_exit_contract(self):
        condition = {
            "kind": "b_cond",
            "condition_code": 0,
            "condition_name": "eq",
        }

        def block(index, start, *, successors=(), edges=(), terminator=None,
                  predicate=None, branch_exit=False, fallthrough_exit=False):
            result = {
                "block_index": index,
                "instruction_start": start,
                "instruction_count": 1,
                "successors": list(successors),
                "successor_edges": [
                    {"target_block": target, "kind": kind}
                    for target, kind in edges
                ],
                "terminator": terminator,
                "external_branch_exit": branch_exit,
                "external_fallthrough_exit": fallthrough_exit,
                "callsite_observations": [],
            }
            if predicate is not None:
                result["terminator_condition"] = dict(predicate)
            return result

        def strict_summary(blocks):
            return {
                "control_flow_instruction_count": len(blocks),
                "control_flow_block_count": len(blocks),
                "control_flow_basic_blocks_truncated": False,
                "control_flow_basic_blocks": blocks,
            }

        valid = strict_summary([
            block(
                0, 0, successors=(1, 2),
                edges=((1, "conditional_taken"), (2, "conditional_fallthrough")),
                terminator="b_cond", predicate=condition,
            ),
            block(1, 1, terminator="return"),
            block(2, 2, terminator="return"),
        ])
        self.assertEqual(
            _summarize_control_flow_helper_paths(valid)["control_flow_path_count"],
            2,
        )

        invalid_summaries = (
            (
                strict_summary([
                    block(
                        0, 0, successors=(1, 2),
                        edges=((1, "conditional_taken"), (2, "conditional_fallthrough")),
                        terminator="b_cond", predicate=condition, branch_exit=True,
                    ),
                    block(1, 1, terminator="return"),
                    block(2, 2, terminator="return"),
                ]),
                "external branch exit flag conflicts",
            ),
            (
                strict_summary([
                    block(
                        0, 0, successors=(1, 2),
                        edges=((1, "conditional_taken"), (2, "conditional_fallthrough")),
                        terminator="b_cond", predicate=condition, fallthrough_exit=True,
                    ),
                    block(1, 1, terminator="return"),
                    block(2, 2, terminator="return"),
                ]),
                "external fallthrough exit flag conflicts",
            ),
            (
                strict_summary([
                    block(
                        0, 0, terminator="b_cond",
                        branch_exit=True, fallthrough_exit=True,
                    ),
                ]),
                "requires a decoded branch predicate",
            ),
            (
                strict_summary([
                    block(
                        0, 0, successors=(1,),
                        edges=((1, "branch_target"),), terminator="return",
                    ),
                    block(1, 1, terminator="return"),
                ]),
                "incompatible with terminator",
            ),
            (
                strict_summary([
                    block(
                        0, 0, terminator="indirect_branch",
                    ),
                    block(1, 1, terminator="return"),
                ]),
                "resolved indirect branch requires exactly one internal target",
            ),
        )
        for summary, message in invalid_summaries:
            with self.subTest(message=message), self.assertRaisesRegex(
                ValueError, message
            ):
                _summarize_control_flow_helper_paths(summary)

        missing_exit_flag = strict_summary([
            block(0, 0, terminator="return"),
        ])
        del missing_exit_flag["control_flow_basic_blocks"][0]["external_branch_exit"]
        with self.assertRaisesRegex(ValueError, "require boolean branch and fallthrough exit flags"):
            _summarize_control_flow_helper_paths(missing_exit_flag)

    def test_path_summary_requires_boolean_truncation_flag_for_declared_window(self):
        summary = {
            "control_flow_instruction_count": 1,
            "control_flow_block_count": 1,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [{
                "block_index": 0,
                "instruction_start": 0,
                "instruction_count": 1,
                "successors": [],
                "successor_edges": [],
                "terminator": "return",
                "external_branch_exit": False,
                "external_fallthrough_exit": False,
                "callsite_observations": [],
            }],
        }

        for invalid_flag in (1, "false", None):
            with self.subTest(invalid_flag=invalid_flag):
                candidate = dict(summary)
                candidate["control_flow_basic_blocks_truncated"] = invalid_flag
                with self.assertRaisesRegex(
                    ValueError, "truncation flag must be a boolean"
                ):
                    _summarize_control_flow_helper_paths(candidate)

        missing_flag = dict(summary)
        del missing_flag["control_flow_basic_blocks_truncated"]
        with self.assertRaisesRegex(
            ValueError, "require a boolean truncation flag"
        ):
            _summarize_control_flow_helper_paths(missing_flag)

        # Older summaries without a declared instruction window remain
        # compatible when they omit the newer truncation metadata.
        legacy = dict(summary)
        del legacy["control_flow_instruction_count"]
        del legacy["control_flow_basic_blocks_truncated"]
        self.assertEqual(
            _summarize_control_flow_helper_paths(legacy)["control_flow_path_count"],
            1,
        )

    def test_control_flow_paths_preserve_mutually_exclusive_helper_sequences(self):
        summary = {
            "control_flow_block_count": 4,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {"block_index": 0, "successors": [1, 2],
                 "successor_edges": [
                     {"target_block": 1, "kind": "conditional_taken"},
                     {"target_block": 2, "kind": "conditional_fallthrough"},
                 ], "terminator": "b_cond",
                 "terminator_condition": {
                     "kind": "b_cond", "condition_code": 0,
                     "condition_name": "eq",
                 },
                 "callsite_observations": [], "reachable": True},
                {"block_index": 1, "successors": [3],
                 "successor_edges": [
                     {"target_block": 3, "kind": "branch_target"},
                 ], "terminator": "b",
                 "callsite_observations": [
                     {"instruction_index": 1, "kind": "direct_call",
                      "method": "SimpleSerializer::serializeInt"}
                 ], "reachable": True},
                {"block_index": 2, "successors": [3],
                 "successor_edges": [
                     {"target_block": 3, "kind": "branch_target"},
                 ], "terminator": "b",
                 "callsite_observations": [
                     {"instruction_index": 2, "kind": "direct_call",
                      "method": "SimpleSerializer::serializeString"}
                 ], "reachable": True},
                {"block_index": 3, "successors": [], "terminator": "return",
                 "callsite_observations": [], "reachable": True},
            ],
        }

        paths = _summarize_control_flow_helper_paths(summary)

        self.assertEqual(paths["control_flow_path_count"], 2)
        self.assertFalse(paths["control_flow_paths_truncated"])
        legacy_conditions = [
            condition
            for path in paths["control_flow_paths"]
            for condition in path["branch_conditions"]
        ]
        self.assertEqual(len(legacy_conditions), 2)
        self.assertTrue(all(
            "instruction_index" not in condition
            for condition in legacy_conditions
        ))
        self.assertEqual(
            [item["block_indexes"] for item in paths["control_flow_paths"]],
            [[0, 1, 3], [0, 2, 3]],
        )
        self.assertEqual(
            [
                [call.get("method") for call in item["helper_callsite_observations"]]
                for item in paths["control_flow_paths"]
            ],
            [
                ["SimpleSerializer::serializeInt"],
                ["SimpleSerializer::serializeString"],
            ],
        )
        self.assertEqual(
            [
                [call.get("instruction_index") for call in item["helper_callsite_observations"]]
                for item in paths["control_flow_paths"]
            ],
            [[1], [2]],
        )
        self.assertEqual(
            [item["edges"] for item in paths["control_flow_paths"]],
            [
                [
                    {"from_block": 0, "to_block": 1, "kind": "conditional_taken"},
                    {"from_block": 1, "to_block": 3, "kind": "branch_target"},
                ],
                [
                    {"from_block": 0, "to_block": 2, "kind": "conditional_fallthrough"},
                    {"from_block": 2, "to_block": 3, "kind": "branch_target"},
                ],
            ],
        )
        self.assertTrue(all(
            item["exit_kind"] == "return"
            for item in paths["control_flow_paths"]
        ))

    def test_conditional_target_and_fallthrough_remain_distinct_when_converged(self):
        start = 0x5100
        words = (
            self._encode_b_cond(start, start + 4),
            0xD65F03C0,  # ret
        )
        code = b"".join(struct.pack("<I", word) for word in words)
        summary = _summarize_control_flow_serializer_helper_blocks(
            code, start, {}, {}
        )

        blocks = summary["control_flow_basic_blocks"]
        self.assertEqual(blocks[0]["successors"], [1])
        self.assertEqual(
            blocks[0]["successor_edges"],
            [
                {"target_block": 1, "kind": "conditional_taken"},
                {"target_block": 1, "kind": "conditional_fallthrough"},
            ],
        )

        paths = _summarize_control_flow_helper_paths(summary)
        self.assertEqual(paths["control_flow_path_count"], 2)
        self.assertEqual(
            [item["block_indexes"] for item in paths["control_flow_paths"]],
            [[0, 1], [0, 1]],
        )
        self.assertEqual(
            [item["edges"] for item in paths["control_flow_paths"]],
            [
                [{"from_block": 0, "to_block": 1, "kind": "conditional_taken"}],
                [{"from_block": 0, "to_block": 1, "kind": "conditional_fallthrough"}],
            ],
        )

    def test_path_summary_rejects_inconsistent_successor_edge_metadata(self):
        summary = {
            "control_flow_block_count": 2,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {
                    "block_index": 0,
                    "successors": [1],
                    "successor_edges": [
                        {"target_block": 1, "kind": "unknown_edge"},
                    ],
                    "callsite_observations": [],
                },
                {
                    "block_index": 1,
                    "successors": [],
                    "successor_edges": [],
                    "callsite_observations": [],
                    "terminator": "return",
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "edge kind"):
            _summarize_control_flow_helper_paths(summary)

    def test_control_flow_paths_record_back_edges_without_unrolling(self):
        summary = {
            "control_flow_block_count": 3,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {"block_index": 0, "successors": [1, 2], "terminator": "b_cond",
                 "callsite_observations": [], "reachable": True},
                {"block_index": 1, "successors": [0], "terminator": "b",
                 "callsite_observations": [
                     {"instruction_index": 1, "kind": "direct_call",
                      "method": "SimpleSerializer::serializeInt"}
                 ], "reachable": True},
                {"block_index": 2, "successors": [], "terminator": "return",
                 "callsite_observations": [], "reachable": True},
            ],
        }

        paths = _summarize_control_flow_helper_paths(summary)

        self.assertEqual(paths["control_flow_path_cycle_count"], 1)
        self.assertEqual(paths["control_flow_path_count"], 2)
        self.assertEqual(
            [item["exit_kind"] for item in paths["control_flow_paths"]],
            ["cycle", "return"],
        )
        self.assertEqual(
            paths["control_flow_paths"][0]["cycle_target_block"], 0
        )
        self.assertIn("not unrolled", paths["control_flow_path_semantics"])

    def test_control_flow_path_limit_marks_partial_enumeration(self):
        summary = {
            "control_flow_block_count": 4,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {"block_index": 0, "successors": [1, 2, 3], "terminator": "b_cond",
                 "callsite_observations": [], "reachable": True},
                {"block_index": 1, "successors": [], "terminator": "return",
                 "callsite_observations": [], "reachable": True},
                {"block_index": 2, "successors": [], "terminator": "return",
                 "callsite_observations": [], "reachable": True},
                {"block_index": 3, "successors": [], "terminator": "return",
                 "callsite_observations": [], "reachable": True},
            ],
        }

        paths = _summarize_control_flow_helper_paths(summary, max_paths=2)

        self.assertEqual(paths["control_flow_path_count"], 2)
        self.assertTrue(paths["control_flow_paths_truncated"])
        self.assertEqual(paths["control_flow_path_analysis_status"], "truncated")

    def test_control_flow_path_summary_refuses_truncated_cfg_and_bad_edges(self):
        truncated = {
            "control_flow_block_count": 2,
            "control_flow_basic_blocks_truncated": True,
            "control_flow_basic_blocks": [],
        }
        result = _summarize_control_flow_helper_paths(truncated)
        self.assertEqual(result["control_flow_path_analysis_status"], "cfg_truncated")
        self.assertEqual(result["control_flow_paths"], [])

        invalid_edge = {
            "control_flow_block_count": 1,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {"block_index": 0, "successors": [1], "terminator": "b",
                 "callsite_observations": [], "reachable": True},
            ],
        }
        with self.assertRaisesRegex(ValueError, "successor index"):
            _summarize_control_flow_helper_paths(invalid_edge)


    def test_control_flow_depth_limit_is_reported_as_truncated(self):
        summary = {
            "control_flow_block_count": 3,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {"block_index": 0, "successors": [1], "terminator": None,
                 "callsite_observations": [], "reachable": True},
                {"block_index": 1, "successors": [2], "terminator": "b",
                 "callsite_observations": [], "reachable": True},
                {"block_index": 2, "successors": [], "terminator": "return",
                 "callsite_observations": [], "reachable": True},
            ],
        }

        paths = _summarize_control_flow_helper_paths(summary, max_depth=2)

        self.assertEqual(paths["control_flow_path_depth_limit_count"], 1)
        self.assertTrue(paths["control_flow_paths_truncated"])
        self.assertEqual(paths["control_flow_path_analysis_status"], "truncated")
        self.assertEqual(paths["control_flow_paths"][0]["next_block"], 2)

    def test_control_flow_cycle_is_explicit_but_not_mislabeled_as_path_truncation(self):
        summary = {
            "control_flow_block_count": 2,
            "control_flow_basic_blocks_truncated": False,
            "control_flow_basic_blocks": [
                {"block_index": 0, "successors": [1], "terminator": "b",
                 "callsite_observations": [], "reachable": True},
                {"block_index": 1, "successors": [0], "terminator": "b",
                 "callsite_observations": [], "reachable": True},
            ],
        }

        paths = _summarize_control_flow_helper_paths(summary)

        self.assertEqual(paths["control_flow_path_analysis_status"], "bounded_with_cycles")
        self.assertFalse(paths["control_flow_paths_truncated"])
        self.assertEqual(paths["control_flow_path_cycle_count"], 1)



class SerializerDeserializerPathAlignmentTests(unittest.TestCase):
    @staticmethod
    def _summary(*paths, status="bounded", truncated=False):
        return {
            "control_flow_path_analysis_status": status,
            "control_flow_path_count": len(paths),
            "control_flow_paths_truncated": truncated,
            "control_flow_paths": [
                {
                    "exit_kind": exit_kind,
                    "helper_callsite_observations": observations,
                }
                for exit_kind, observations in paths
            ],
        }

    @staticmethod
    def _call(kind, method=None, resolution=None):
        result = {"kind": kind}
        if method is not None:
            result["method"] = method
        if resolution is not None:
            result["resolution"] = resolution
        return result

    def test_primitive_serializer_and_deserializer_names_normalize_to_same_families(self):
        serializer = self._summary((
            "return",
            [
                self._call("direct_call", method="SimpleSerializer::serializeInt"),
                self._call("indirect_call", method="SimpleSerializer::serializeString"),
            ],
        ))
        deserializer = self._summary((
            "return",
            [
                self._call("direct_call", method="SimpleDeserializer::deserializeInt"),
                self._call("indirect_call", method="SimpleDeserializer::deserializeString"),
            ],
        ))

        result = _summarize_serializer_deserializer_path_alignment(
            serializer, deserializer
        )

        self.assertEqual(result["comparison_status"], "bounded")
        self.assertEqual(result["shared_path_signature_count"], 1)
        self.assertEqual(result["shared_path_instance_count"], 1)
        self.assertEqual(
            result["shared_path_signatures"][0]["helper_families"],
            ["Int", "String"],
        )
        self.assertEqual(result["path_pair_count"], 1)
        self.assertEqual(result["maximum_common_helper_prefix_length"], 2)
        self.assertEqual(result["maximum_common_helper_prefix_pair_count"], 1)
        self.assertEqual(
            result["common_helper_prefix_length_histogram"],
            [{"prefix_length": 2, "path_pair_count": 1}],
        )
        self.assertFalse(result["field_order_inferred"])

    def test_branch_exclusive_helper_sequences_are_not_flattened_together(self):
        serializer = self._summary(
            ("return", [self._call("direct_call", method="SimpleSerializer::serializeInt")]),
            ("return", [self._call("direct_call", method="SimpleSerializer::serializeString")]),
        )
        deserializer = self._summary(
            ("return", [self._call("direct_call", method="SimpleDeserializer::deserializeInt")]),
            ("return", [self._call("direct_call", method="SimpleDeserializer::deserializeBoolean")]),
        )

        result = _summarize_serializer_deserializer_path_alignment(
            serializer, deserializer
        )

        self.assertEqual(result["shared_path_instance_count"], 1)
        self.assertEqual(result["serializer_only_path_instance_count"], 1)
        self.assertEqual(result["deserializer_only_path_instance_count"], 1)
        self.assertEqual(
            result["serializer_only_path_signatures"][0]["helper_families"],
            ["String"],
        )
        self.assertEqual(
            result["deserializer_only_path_signatures"][0]["helper_families"],
            ["Boolean"],
        )

    def test_unresolved_calls_remain_explicit_and_truncated_inputs_are_partial(self):
        serializer = self._summary(
            ("return", [
                self._call("direct_call", method="SimpleSerializer::serializeInt"),
                self._call(
                    "indirect_call",
                    resolution="not_resolved_as_serializer_helper",
                ),
            ]),
            status="truncated",
            truncated=True,
        )
        deserializer = self._summary(
            ("return", [
                self._call("direct_call", method="SimpleDeserializer::deserializeInt"),
            ]),
        )

        result = _summarize_serializer_deserializer_path_alignment(
            serializer, deserializer
        )

        self.assertEqual(result["comparison_status"], "partial")
        self.assertEqual(result["serializer_unresolved_observation_count"], 1)
        self.assertEqual(result["shared_path_signature_count"], 0)
        self.assertEqual(
            result["serializer_only_path_signatures"][0]["unresolved_observations"],
            [{
                "kind": "indirect_call",
                "resolution": "not_resolved_as_serializer_helper",
            }],
        )

    def test_path_alignment_reports_common_prefix_before_branch_divergence(self):
        serializer = self._summary(
            ("return", [
                self._call("direct_call", method="SimpleSerializer::serializeInt"),
                self._call("direct_call", method="SimpleSerializer::serializeString"),
            ]),
            ("return", [
                self._call("direct_call", method="SimpleSerializer::serializeInt"),
                self._call("direct_call", method="SimpleSerializer::serializeBoolean"),
            ]),
        )
        deserializer = self._summary(
            ("return", [
                self._call("direct_call", method="SimpleDeserializer::deserializeInt"),
                self._call("direct_call", method="SimpleDeserializer::deserializeLong"),
            ]),
            ("return", [
                self._call("direct_call", method="SimpleDeserializer::deserializeBoolean"),
            ]),
        )

        result = _summarize_serializer_deserializer_path_alignment(
            serializer, deserializer
        )

        self.assertEqual(result["path_pair_count"], 4)
        self.assertEqual(result["maximum_common_helper_prefix_length"], 1)
        self.assertEqual(result["maximum_common_helper_prefix_pair_count"], 2)
        self.assertEqual(
            result["common_helper_prefix_length_histogram"],
            [
                {"prefix_length": 0, "path_pair_count": 2},
                {"prefix_length": 1, "path_pair_count": 2},
            ],
        )
        self.assertFalse(result["field_order_inferred"])

    def test_path_alignment_with_empty_side_reports_zero_path_pairs(self):
        serializer = self._summary((
            "return",
            [self._call("direct_call", method="SimpleSerializer::serializeInt")],
        ))
        deserializer = self._summary()

        result = _summarize_serializer_deserializer_path_alignment(
            serializer, deserializer
        )

        self.assertEqual(result["path_pair_count"], 0)
        self.assertEqual(result["maximum_common_helper_prefix_length"], 0)
        self.assertEqual(result["maximum_common_helper_prefix_pair_count"], 0)
        self.assertEqual(result["common_helper_prefix_length_histogram"], [])

    def test_path_alignment_aggregates_the_maximum_bounded_pair_matrix(self):
        serializer_paths = tuple(
            ("return", [
                self._call("direct_call", method="SimpleSerializer::serializeInt")
            ])
            for _ in range(256)
        )
        deserializer_paths = tuple(
            ("return", [
                self._call("direct_call", method="SimpleDeserializer::deserializeInt")
            ])
            for _ in range(256)
        )

        result = _summarize_serializer_deserializer_path_alignment(
            self._summary(*serializer_paths),
            self._summary(*deserializer_paths),
        )

        self.assertEqual(result["path_pair_count"], 65_536)
        self.assertEqual(
            result["common_helper_prefix_length_histogram"],
            [{"prefix_length": 1, "path_pair_count": 65_536}],
        )
        self.assertEqual(result["maximum_common_helper_prefix_pair_count"], 65_536)

    def test_path_alignment_rejects_more_than_the_producer_path_limit(self):
        serializer = self._summary(*(
            ("return", [
                self._call("direct_call", method="SimpleSerializer::serializeInt")
            ])
            for _ in range(257)
        ))

        with self.assertRaisesRegex(ValueError, "path count exceeds 256"):
            _summarize_serializer_deserializer_path_alignment(
                serializer, self._summary()
            )

    def test_path_alignment_rejects_observations_larger_than_the_entry_window(self):
        serializer = self._summary((
            "return",
            [
                self._call("direct_call", method="SimpleSerializer::serializeInt")
                for _ in range(16_385)
            ],
        ))

        with self.assertRaisesRegex(ValueError, "path observations exceed 16384"):
            _summarize_serializer_deserializer_path_alignment(
                serializer, self._summary()
            )

    def test_malformed_path_counts_and_observations_fail_closed(self):
        serializer = self._summary(
            ("return", [self._call("direct_call", method="SimpleSerializer::serializeInt")])
        )
        serializer["control_flow_path_count"] = 2
        deserializer = self._summary()
        with self.assertRaisesRegex(ValueError, "path count"):
            _summarize_serializer_deserializer_path_alignment(
                serializer, deserializer
            )

        malformed = self._summary(("return", [{"kind": "direct_call"}]))
        with self.assertRaisesRegex(ValueError, "no method or resolution"):
            _summarize_serializer_deserializer_path_alignment(
                malformed, deserializer
            )

    def test_login_session_pairs_are_grouped_by_metadata_type_and_image(self):
        serializer = self._summary((
            "return",
            [self._call("direct_call", method="SimpleSerializer::serializeInt")],
        ))
        deserializer = self._summary((
            "return",
            [self._call("direct_call", method="SimpleDeserializer::deserializeInt")],
        ))
        entries = [
            {
                "type": "LoginRequestSTSerializer",
                "method": "serialize",
                "image": "ScriptsAssembly.dll",
                **serializer,
            },
            {
                "type": "LoginRequestSTDeserializer",
                "method": "deserialize",
                "image": "ScriptsAssembly.dll",
                **deserializer,
            },
        ]

        comparisons = _compare_login_session_serializer_paths(entries)

        self.assertEqual(len(comparisons), 1)
        self.assertEqual(comparisons[0]["message_type"], "LoginRequest")
        self.assertEqual(comparisons[0]["comparison_status"], "bounded")
        self.assertEqual(comparisons[0]["shared_path_instance_count"], 1)

    def test_truncated_entry_window_makes_pair_comparison_partial(self):
        serializer = self._summary((
            "return",
            [self._call("direct_call", method="SimpleSerializer::serializeInt")],
        ))
        deserializer = self._summary((
            "return",
            [self._call("direct_call", method="SimpleDeserializer::deserializeInt")],
        ))
        entries = [
            {
                "type": "LoginRequestSTSerializer",
                "method": "serialize",
                "image": "ScriptsAssembly.dll",
                "entry_window_truncated": True,
                **serializer,
            },
            {
                "type": "LoginRequestSTDeserializer",
                "method": "deserialize",
                "image": "ScriptsAssembly.dll",
                "entry_window_truncated": False,
                **deserializer,
            },
        ]

        comparison = _compare_login_session_serializer_paths(entries)[0]

        self.assertEqual(comparison["comparison_status"], "partial")
        self.assertTrue(comparison["serializer_entry_window_truncated"])
        self.assertFalse(comparison["deserializer_entry_window_truncated"])

    def test_missing_or_ambiguous_pair_is_reported_without_guessing(self):
        entry = {
            "type": "SessionRestoreRequestSTSerializer",
            "method": "serialize",
            "image": "ScriptsAssembly.dll",
        }
        comparisons = _compare_login_session_serializer_paths([entry, dict(entry)])
        self.assertEqual(len(comparisons), 1)
        self.assertEqual(
            comparisons[0]["comparison_status"], "unpaired_or_ambiguous"
        )
        self.assertEqual(comparisons[0]["serializer_entry_count"], 2)
        self.assertEqual(comparisons[0]["deserializer_entry_count"], 0)



class ReceiverIntegerLookupEvidenceTests(unittest.TestCase):
    @staticmethod
    def _encode_adrp(register, pc, target):
        immediate = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
        if not -(1 << 20) <= immediate < (1 << 20):
            raise ValueError("ADRP target out of range")
        immediate &= (1 << 21) - 1
        return (
            0x90000000 | ((immediate & 0x3) << 29)
            | (((immediate >> 2) & 0x7FFFF) << 5) | register
        )

    @staticmethod
    def _encode_ldr_x(target, base, byte_offset):
        if byte_offset % 8 or not 0 <= byte_offset // 8 < 4096:
            raise ValueError("invalid LDR offset")
        return 0xF9400000 | ((byte_offset // 8) << 10) | (base << 5) | target

    @staticmethod
    def _encode_str_x(target, base, byte_offset):
        if byte_offset % 8 or not 0 <= byte_offset // 8 < 4096:
            raise ValueError("invalid STR offset")
        return 0xF9000000 | ((byte_offset // 8) << 10) | (base << 5) | target

    @staticmethod
    def _encode_mov_w(destination, source):
        return 0x2A0003E0 | (source << 16) | destination

    @staticmethod
    def _encode_bl(pc, target):
        delta = target - pc
        if delta % 4:
            raise ValueError("unaligned BL target")
        return 0x94000000 | ((delta >> 2) & 0x03FFFFFF)

    @staticmethod
    def _code(words):
        return b"".join(struct.pack("<I", word) for word in words)

    def _synthetic_windows(self, *, key_source=20, key_argument=20, class_cell=0x2970,
                           deserialize_count=2):
        start = 0x1000
        deserialize_target = 0x3000
        lookup_target = 0x4000
        cctor = self._code([
            self._encode_adrp(20, start, class_cell),
            0xD503201F,
            self._encode_ldr_x(20, 20, class_cell - (start & ~0xFFF)),
            self._encode_ldr_x(8, 20, 0),
            self._encode_ldr_x(8, 8, 0xB8),
            self._encode_str_x(19, 8, 0),
            0xD65F03C0,
        ])
        receiver_words = [
            self._encode_adrp(28, start, class_cell),
            self._encode_ldr_x(28, 28, class_cell - (start & ~0xFFF)),
        ]
        for index in range(deserialize_count):
            pc = start + len(receiver_words) * 4
            receiver_words.append(self._encode_bl(pc, deserialize_target))
        if deserialize_count == 2:
            receiver_words.extend([
                self._encode_mov_w(key_source, 0),
                self._encode_ldr_x(0, 28, 0),
                self._encode_ldr_x(8, 0, 0xB8),
                self._encode_ldr_x(0, 8, 0),
                self._encode_mov_w(1, key_argument),
                self._encode_bl(start + (len(receiver_words) + 5) * 4, lookup_target),
                0xD65F03C0,
            ])
        return start, cctor, self._code(receiver_words), deserialize_target, lookup_target

    def test_decodes_static_store_and_32_bit_register_move(self):
        self.assertEqual(
            _decode_aarch64_str_x_unsigned(self._encode_str_x(19, 8, 0)),
            (19, 8, 0),
        )
        self.assertEqual(
            _decode_aarch64_mov_w_register(self._encode_mov_w(20, 0)),
            (20, 0),
        )
        self.assertIsNone(_decode_aarch64_mov_w_register(0xAA0003F4))

    def test_second_receive_integer_is_forwarded_to_static_slot_lookup_candidate(self):
        start, cctor, receiver, deserialize_target, lookup_target = self._synthetic_windows()
        summary, target = _summarize_receiver_integer_lookup(
            receiver, start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "static_key_lookup_candidate")
        self.assertEqual(summary["deserialize_int_call_count"], 2)
        self.assertEqual(summary["source_call_ordinal"], 2)
        self.assertTrue(summary["second_result_copied_from_w0"])
        self.assertTrue(summary["key_forwarded_to_w1"])
        self.assertTrue(summary["networksettings_static_first_slot_store_observed"])
        self.assertTrue(summary["networksettings_static_first_slot_read_observed"])
        self.assertEqual(summary["field_candidate_name"], "m_zippetMessageTypes")
        self.assertEqual(summary["field_attribution_status"], "metadata_order_candidate_only")
        self.assertEqual(target, lookup_target)
        self.assertFalse(summary["wire_message_id_verified"])
        self.assertFalse(summary["compression_behavior_verified"])
        self.assertFalse(summary["wire_contract_verified"])
        self.assertFalse(summary["apk_compatible"])
        rendered = json.dumps(summary)
        self.assertNotIn("0x", rendered)
        self.assertNotIn(hex(lookup_target), rendered)

    def test_truncated_receiver_or_cctor_window_never_produces_lookup_candidate(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows()
        cases = (
            ({"receiver_window_truncated": True}, True, False),
            ({"networksettings_cctor_window_truncated": True}, False, True),
            ({
                "receiver_window_truncated": True,
                "networksettings_cctor_window_truncated": True,
            }, True, True),
        )
        for kwargs, receiver_truncated, cctor_truncated in cases:
            with self.subTest(kwargs=kwargs):
                summary, target = _summarize_receiver_integer_lookup(
                    receiver, start, cctor, start, {deserialize_target}, set(), None,
                    **kwargs,
                )
                self.assertEqual(summary["status"], "unresolved_truncated_entry_window")
                self.assertIs(
                    summary["receiver_entry_window_truncated"], receiver_truncated
                )
                self.assertIs(
                    summary["networksettings_cctor_entry_window_truncated"],
                    cctor_truncated,
                )
                self.assertIsNone(target)
                self.assertFalse(summary["wire_message_id_verified"])
                self.assertFalse(summary["compression_behavior_verified"])
                self.assertFalse(summary["wire_contract_verified"])
                self.assertFalse(summary["apk_compatible"])

    def test_entry_window_truncation_flags_require_builtin_booleans(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows()
        for kwargs in (
            {"receiver_window_truncated": 1},
            {"networksettings_cctor_window_truncated": None},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                ValueError, "entry-window truncation flags"
            ):
                _summarize_receiver_integer_lookup(
                    receiver, start, cctor, start, {deserialize_target}, set(), None,
                    **kwargs,
                )

    def test_inspect_bytes_passes_truncation_flags_to_receiver_lookup_gate(self):
        from unittest.mock import patch

        metadata = make_metadata(["Cycle"], type_name="Receiver")
        network_methods = [
            {
                "namespace": "com.geargames.common.network",
                "type": "Receiver",
                "method": "Cycle",
                "parameter_count": 0,
                "image": "ScriptsAssembly.dll",
                "category": "network",
                "slot_index": 0,
            },
            {
                "namespace": "com.geargames.common.network",
                "type": "NetworkSettings",
                "method": ".cctor",
                "parameter_count": 0,
                "image": "ScriptsAssembly.dll",
                "category": "network",
                "slot_index": 1,
            },
        ]
        helper_methods = [
            {
                "namespace": "com.geargames.serialization",
                "type": "SimpleDeserializer",
                "method": "deserializeInt",
                "parameter_count": 1,
                "image": "ScriptsAssembly.dll",
                "category": "serializer_helper",
                "slot_index": 2,
            },
        ]

        def fake_network_methods(_metadata, _info, allowlist_map=None):
            return network_methods if allowlist_map is None else helper_methods

        sections = {
            ".text": {
                "type": 1,
                "flags": 0x4,
                "address": 0x5000,
                "offset": 0,
                "size": 64,
            },
        }
        relocations = {
            0x1000: (R_AARCH64_RELATIVE, 0x5000),
            0x1008: (R_AARCH64_RELATIVE, 0x5004),
            0x1010: (R_AARCH64_RELATIVE, 0x5008),
        }
        tables = {"ScriptsAssembly.dll": 0x1000}

        for receiver_truncated, cctor_truncated in ((True, False), (False, True)):
            windows = {
                (".text", 0x5000): (4, receiver_truncated),
                (".text", 0x5004): (4, cctor_truncated),
                (".text", 0x5008): (4, False),
            }
            with self.subTest(
                receiver_truncated=receiver_truncated,
                cctor_truncated=cctor_truncated,
            ), patch(
                "tools.il2cpp_native_method_evidence._network_methods",
                side_effect=fake_network_methods,
            ), patch(
                "tools.il2cpp_native_method_evidence._module_tables",
                return_value=(sections, relocations, tables),
            ), patch(
                "tools.il2cpp_native_method_evidence._entrypoint_windows",
                return_value=windows,
            ), patch(
                "tools.il2cpp_native_method_evidence._direct_branch_targets",
                return_value=set(),
            ), patch(
                "tools.il2cpp_native_method_evidence._relocated_indirect_call_targets",
                return_value=set(),
            ), patch(
                "tools.il2cpp_native_method_evidence._all_method_targets",
                return_value={},
            ):
                report = inspect_bytes(metadata, bytes(64))

            summary = report["receiver_integer_lookup_summary"]
            self.assertEqual(summary["status"], "unresolved_truncated_entry_window")
            self.assertIs(
                summary["receiver_entry_window_truncated"], receiver_truncated
            )
            self.assertIs(
                summary["networksettings_cctor_entry_window_truncated"],
                cctor_truncated,
            )
            self.assertFalse(summary["wire_contract_verified"])
            self.assertFalse(summary["apk_compatible"])

    def test_rejects_second_integer_when_key_register_is_not_forwarded(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows(
            key_argument=19
        )
        summary, target = _summarize_receiver_integer_lookup(
            receiver, start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "unresolved_key_argument")
        self.assertIsNone(target)

    def test_rejects_static_slot_from_a_different_class_cell(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows(
            class_cell=0x2970
        )
        other_cell = 0x3970
        receiver_words = [
            self._encode_adrp(28, start, other_cell),
            self._encode_ldr_x(28, 28, other_cell - (start & ~0xFFF)),
            self._encode_bl(start + 8, deserialize_target),
            self._encode_bl(start + 12, deserialize_target),
            self._encode_mov_w(20, 0),
            self._encode_ldr_x(0, 28, 0),
            self._encode_ldr_x(8, 0, 0xB8),
            self._encode_ldr_x(0, 8, 0),
            self._encode_mov_w(1, 20),
            self._encode_bl(start + 36, 0x4000),
        ]
        summary, target = _summarize_receiver_integer_lookup(
            self._code(receiver_words), start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "unresolved_networksettings_static_slot_read")
        self.assertIsNone(target)

    def test_requires_two_direct_deserializer_calls(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows(
            deserialize_count=1
        )
        summary, target = _summarize_receiver_integer_lookup(
            receiver, start, cctor, start, {deserialize_target}, set(), None,
        )
        self.assertEqual(summary["status"], "unresolved_deserialize_call_count")
        self.assertEqual(summary["deserialize_int_call_count"], 1)
        self.assertIsNone(target)

    def test_networksettings_first_non_default_field_is_only_a_metadata_candidate(self):
        metadata = make_metadata(
            [".cctor"],
            type_name="NetworkSettings",
            fields=(
                ("HeaderLength", 1, 0x04000001),
                ("m_zippetMessageTypes", 2, 0x04000002),
                ("m_notSessionedMessageTypes", 3, 0x04000003),
            ),
            default_fields=(0,),
        )
        candidate = _networksettings_first_non_default_field(metadata)
        self.assertEqual(candidate["name"], "m_zippetMessageTypes")
        self.assertEqual(candidate["leading_default_backed_field_count"], 1)
        self.assertEqual(candidate["field_count"], 3)

    def test_bucketed_lookup_shape_requires_register_linked_modulo_and_entry_chain(self):
        # Synthetic AArch64 instruction vector; not copied from the APK.
        words = [
            0x1AC70CC5,  # sdiv w5, w6, w7
            0x1B0798A5,  # msub w5, w5, w7, w6
            0x6B0700BF,  # cmp w5, w7
            0x54000222,  # b.hs
            0x8B254928,  # add x8, x9, w5, uxtw #2
            0xB940210A,  # ldr w10, [x8, #0x20]
            0x7100054B,  # subs w11, w10, #1
            0x540001A4,  # b.mi
            0xF9400E8F,  # ldr x15, [x20, #0x18]
            0x910081EF,  # add x15, x15, #0x20
            0x5280018C,  # mov w12, #12
            0x9BAC7D6D,  # umull x13, w11, w12
            0xB86D69EE,  # ldr w14, [x15, x13]
            0x6B0601DF,  # cmp w14, w6
            0x54000081,  # b.ne
            0x9BAC3D70,  # umaddl x16, w11, w12, x15
            0xB9400A11,  # ldr w17, [x16, #8]
            0xD63F0240,  # blr x18
            0xB9400613,  # ldr w19, [x16, #4]
            0x36F80013,  # tbz w19, #31
            0xD65F03C0,  # ret
        ]
        summary = _summarize_bucketed_lookup_shape(self._code(words))
        self.assertEqual(
            summary,
            {
                "status": "bucketed_membership_lookup_shape_candidate",
                "hash_modulo_bucket_index": True,
                "bucket_head_sentinel_check": True,
                "entry_stride_bytes": 12,
                "entry_hash_comparison": True,
                "indirect_comparer_dispatch": True,
                "entry_next_index_traversal": True,
                "entry_value_offset_bytes": 8,
                "entry_next_index_offset_bytes": 4,
                "managed_method_identity_verified": False,
                "managed_collection_owner_verified": False,
            },
        )
        rendered = json.dumps(summary)
        self.assertNotIn("0x", rendered)
        self.assertNotIn("instruction_word", rendered)

    def test_bucketed_lookup_shape_fails_closed_on_register_or_layout_mismatch(self):
        base_words = [
            0x1AC70CC5, 0x1B0798A5, 0x6B0700BF, 0x54000222,
            0x8B254928, 0xB940210A, 0x7100054B, 0x540001A4,
            0xF9400E8F, 0x910081EF, 0x5280018C, 0x9BAC7D6D,
            0xB86D69EE, 0x6B0601DF, 0x54000081, 0x9BAC3D70,
            0xB9400A11, 0xD63F0240, 0xB9400613, 0x36F80013,
            0xD65F03C0,
        ]
        wrong_divisor = list(base_words)
        wrong_divisor[1] = (
            (wrong_divisor[1] & ~(0x1F << 16)) | (8 << 16)
        )
        wrong_stride = list(base_words)
        wrong_stride[10] = 0x5280020C  # mov w12, #16
        missing_comparer = list(base_words)
        missing_comparer[17] = 0xD503201F
        missing_chain = list(base_words)
        missing_chain[18] = 0xD503201F

        for label, words in (
            ("wrong divisor register", wrong_divisor),
            ("wrong entry stride", wrong_stride),
            ("missing comparer call", missing_comparer),
            ("missing next-entry load", missing_chain),
        ):
            with self.subTest(label=label):
                summary = _summarize_bucketed_lookup_shape(self._code(words))
                self.assertEqual(summary["status"], "unresolved")
                self.assertFalse(summary["managed_method_identity_verified"])
                self.assertFalse(summary["managed_collection_owner_verified"])

    def test_bucketed_lookup_shape_rejects_unaligned_instruction_bytes(self):
        with self.assertRaisesRegex(ValueError, "aligned AArch64 bytes"):
            _summarize_bucketed_lookup_shape(b"\x00\x00\x00")

    def test_hash_bucket_opcode_families_are_not_reported_as_a_shape(self):
        words = [0x1ACA0C09, 0x1B0A8129, 0xB9401908, 0x6B0A013F, 0x54000561]
        self.assertTrue(_contains_hash_bucket_opcode_families(self._code(words)))
        self.assertTrue(_contains_hash_bucket_opcode_families(self._code(list(reversed(words)))))
        self.assertFalse(_contains_hash_bucket_opcode_families(self._code(words[:1] + words[2:])))


    def test_rejects_w0_clobber_before_second_result_copy(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows()
        words = [struct.unpack_from("<I", receiver, offset)[0] for offset in range(0, len(receiver), 4)]
        words.insert(4, self._encode_mov_w(0, 21))
        summary, target = _summarize_receiver_integer_lookup(
            self._code(words), start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "unresolved_second_result_copy")
        self.assertIsNone(target)

    def test_rejects_key_register_alias_with_static_slot_load(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows(
            key_source=8
        )
        summary, target = _summarize_receiver_integer_lookup(
            receiver, start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "unresolved_key_register_alias")
        self.assertIsNone(target)

    def test_requires_direct_lookup_call_after_key_argument_move(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows()
        words = [struct.unpack_from("<I", receiver, offset)[0] for offset in range(0, len(receiver), 4)]
        words.insert(9, self._encode_mov_w(1, 22))
        summary, target = _summarize_receiver_integer_lookup(
            self._code(words), start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "unresolved_lookup_call")
        self.assertIsNone(target)

    def test_rejects_non_nop_gap_in_static_slot_read_chain(self):
        start, cctor, receiver, deserialize_target, _lookup_target = self._synthetic_windows()
        words = [struct.unpack_from("<I", receiver, offset)[0] for offset in range(0, len(receiver), 4)]
        words.insert(6, self._encode_mov_w(8, 19))
        summary, target = _summarize_receiver_integer_lookup(
            self._code(words), start, cctor, start, {deserialize_target}, set(),
            {"name": "m_zippetMessageTypes", "leading_default_backed_field_count": 20},
        )
        self.assertEqual(summary["status"], "unresolved_networksettings_static_slot_read")
        self.assertIsNone(target)

    def test_network_field_summary_includes_zipped_message_collection_names(self):
        metadata = make_metadata(
            [".cctor"],
            type_name="NetworkSettings",
            fields=(
                ("HeaderLength", 1, 0x04000001),
                ("m_zippetMessageTypes", 2, 0x04000002),
                ("m_notSessionedMessageTypes", 3, 0x04000003),
                ("m_notEnumeratedMessageTypes", 4, 0x04000004),
                ("m_unimportantMessageTypes", 5, 0x04000005),
            ),
            default_fields=(0,),
        )
        report = inspect_bytes(metadata, make_elf(1))
        fields = {item["field"]: item for item in report["network_field_summary"]}
        self.assertEqual(
            set(fields),
            {
                "HeaderLength", "m_zippetMessageTypes",
                "m_notSessionedMessageTypes", "m_notEnumeratedMessageTypes",
                "m_unimportantMessageTypes",
            },
        )
        self.assertTrue(fields["HeaderLength"]["has_default_value"])
        self.assertFalse(fields["m_zippetMessageTypes"]["has_default_value"])


class EntryPointWindowBoundsTests(unittest.TestCase):
    def _single_window(self, section_size):
        section = {
            "type": 1,
            "flags": 0x4,
            "address": 0x1000,
            "size": section_size,
        }
        return _entrypoint_windows(
            {"text": section},
            {0x2000: (R_AARCH64_RELATIVE, 0x1000)},
            {"ScriptsAssembly.dll": 0x2000},
            [{"name": "ScriptsAssembly.dll", "method_count": 1}],
            [("text", section)],
        )[("text", 0x1000)]

    def test_non_word_aligned_section_tail_marks_window_truncated(self):
        # The analyzer retains only complete AArch64 instructions (4-byte
        # units); the two omitted bytes must not be reported as a complete
        # method window.
        self.assertEqual(self._single_window(10), (8, True))

    def test_word_aligned_section_end_keeps_window_complete(self):
        self.assertEqual(self._single_window(12), (12, False))

    def test_entry_window_cap_marks_window_truncated(self):
        self.assertEqual(
            self._single_window(MAX_ENTRYPOINT_WINDOW_BYTES + 4),
            (MAX_ENTRYPOINT_WINDOW_BYTES, True),
        )


if __name__ == "__main__":
    unittest.main()
