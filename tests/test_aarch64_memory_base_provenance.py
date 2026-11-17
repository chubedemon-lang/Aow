"""Synthetic AArch64 memory-base provenance tests; no APK bytes are used."""
import json
import struct
import unittest

from tools.aarch64_memory_base_provenance import (
    _decode_adrp,
    summarize_control_flow_memory_base_provenance,
)


def code_bytes(*words):
    return b"".join(struct.pack("<I", word) for word in words)


def adrp(register, pc, target_page):
    delta = (target_page & ~0xFFF) - (pc & ~0xFFF)
    pages = delta >> 12
    if not -(1 << 20) <= pages < (1 << 20):
        raise ValueError("ADRP target out of range")
    immediate = pages & ((1 << 21) - 1)
    return (
        0x90000000
        | ((immediate & 0x3) << 29)
        | (((immediate >> 2) & 0x7FFFF) << 5)
        | register
    )


def add_x(destination, source, immediate):
    return 0x91000000 | (immediate << 10) | (source << 5) | destination


def mov_x(destination, source):
    return 0xAA0003E0 | (source << 16) | destination


def ldr_x(destination, base, immediate=0):
    return (3 << 30) | 0x39400000 | (immediate << 10) | (base << 5) | destination


def str_w(source, base, immediate=0):
    return (2 << 30) | 0x39000000 | (immediate << 10) | (base << 5) | source


class AArch64MemoryBaseProvenanceTests(unittest.TestCase):
    def test_decodes_positive_and_negative_adrp_page_targets(self):
        pc = 0x10001234
        positive = _decode_adrp(adrp(8, pc, 0x10008000), pc)
        negative = _decode_adrp(adrp(9, pc, 0x0FFF8000), pc)
        self.assertEqual(positive, (8, 0x10008000))
        self.assertEqual(negative, (9, 0x0FFF8000))
        self.assertIsNone(_decode_adrp(0xD503201F, pc))

    def test_tracks_adrp_add_and_mov_into_store_base(self):
        start = 0x1000
        words = (
            adrp(8, start, 0x6000),
            add_x(8, 8, 0x120),
            mov_x(9, 8),
            str_w(0, 9, 2),
        )
        result = summarize_control_flow_memory_base_provenance(code_bytes(*words), start)
        access = result["memory_accesses"][0]
        self.assertEqual(access["base_register"], "x9")
        self.assertEqual(access["base_provenance"], "adrp_derived_address")
        self.assertEqual(access["base_definition_instruction_index"], 1)
        self.assertEqual(access["base_derivation_depth"], 3)
        self.assertEqual(result["memory_accesses_with_known_base_provenance"], 1)

    def test_tracks_relocation_backed_pointer_load_without_emitting_addresses(self):
        start = 0x1000
        slot = 0x5040
        target = 0x9000
        words = (
            adrp(8, start, 0x5000),
            add_x(8, 8, 0x40),
            ldr_x(9, 8),
            str_w(0, 9, 3),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, relocation_targets={slot: target}
        )
        access = result["memory_accesses"][-1]
        self.assertEqual(access["base_provenance"], "relocation_loaded_pointer")
        self.assertEqual(access["base_definition_instruction_index"], 2)
        self.assertEqual(access["base_derivation_depth"], 1)
        rendered = json.dumps(result)
        self.assertNotIn(hex(slot), rendered)
        self.assertNotIn(hex(target), rendered)
        self.assertFalse(result["absolute_addresses_emitted"])
        self.assertFalse(result["raw_instructions_emitted"])

    def test_unknown_instruction_and_call_clear_address_state(self):
        start = 0x2000
        prefix = (adrp(8, start, 0x7000), add_x(8, 8, 0x20))
        after_unknown = summarize_control_flow_memory_base_provenance(
            code_bytes(*(prefix + (0xFFFFFFFF, str_w(0, 8)))), start
        )
        after_call = summarize_control_flow_memory_base_provenance(
            code_bytes(*(prefix + (0x94000000, str_w(0, 8)))), start
        )
        self.assertEqual(after_unknown["memory_accesses"][0]["base_provenance"], "unknown")
        self.assertEqual(after_call["memory_accesses"][0]["base_provenance"], "unknown")

    def test_conditional_join_drops_ambiguous_register_state(self):
        start = 0x3000
        conditional = 0x54000000 | (3 << 5)
        words = (
            adrp(8, start, 0x8000),
            conditional,
            add_x(8, 8, 0x10),
            0x14000001,  # B to instruction 4
            str_w(0, 8),
        )
        result = summarize_control_flow_memory_base_provenance(code_bytes(*words), start)
        self.assertEqual(result["memory_accesses"][0]["base_provenance"], "unknown")
        self.assertEqual(result["statically_reachable_memory_access_count"], 1)
        self.assertEqual(result["statically_unreachable_memory_access_count"], 0)

    def test_unconditional_branch_counts_but_does_not_analyze_skipped_access(self):
        access = str_w(0, 8)
        words = (0x14000002, access, access)
        result = summarize_control_flow_memory_base_provenance(code_bytes(*words), 0x3800)
        self.assertEqual(result["memory_access_count"], 2)
        self.assertEqual(result["statically_reachable_memory_access_count"], 1)
        self.assertEqual(result["statically_unreachable_memory_access_count"], 1)
        self.assertEqual(len(result["memory_accesses"]), 1)

    def test_stack_pointer_is_reported_without_register_tracking(self):
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(str_w(0, 31, 1)), 0x4000
        )
        self.assertEqual(result["memory_accesses"][0]["base_provenance"], "stack_pointer")

    def test_rejects_invalid_input_and_relocation_maps(self):
        invalid = (
            (b"abc", 0x1000, None, 128),
            (b"1234", True, None, 128),
            (b"1234", 0x1001, None, 128),
            (b"", 0x1000, None, 0),
            (b"", 0x1000, None, True),
            (b"", 0x1000, [], 128),
            (b"", 0x1000, {True: 0x1000}, 128),
            (b"", 0x1000, {0x1000: False}, 128),
        )
        for code, start, relocations, limit in invalid:
            with self.subTest(code=code, start=start, relocations=relocations, limit=limit):
                with self.assertRaises(ValueError):
                    summarize_control_flow_memory_base_provenance(
                        code, start, relocation_targets=relocations, max_accesses=limit
                    )

    def test_empty_and_truncated_reports_preserve_total_count(self):
        self.assertEqual(
            summarize_control_flow_memory_base_provenance(b"", 0x5000)["memory_access_count"],
            0,
        )
        words = (str_w(0, 31), str_w(1, 31, 1))
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), 0x6000, max_accesses=1
        )
        self.assertEqual(result["memory_access_count"], 2)
        self.assertEqual(result["statically_reachable_memory_access_count"], 2)
        self.assertEqual(len(result["memory_accesses"]), 1)
        self.assertTrue(result["memory_accesses_truncated"])


if __name__ == "__main__":
    unittest.main()
