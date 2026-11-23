"""Synthetic AArch64 memory-base provenance tests; no APK bytes are used."""
import builtins
import json
import struct
import unittest
from unittest.mock import patch

from tools.aarch64_memory_base_provenance import (
    _decode_adr,
    _decode_adrp,
    _decode_ldr_literal,
    _validate_relocation_targets,
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


def adr(register, pc, target):
    offset = target - pc
    if not -(1 << 20) <= offset < (1 << 20):
        raise ValueError("ADR target out of range")
    immediate = offset & ((1 << 21) - 1)
    return (
        0x10000000
        | ((immediate & 0x3) << 29)
        | (((immediate >> 2) & 0x7FFFF) << 5)
        | register
    )


def add_x(destination, source, immediate):
    return 0x91000000 | (immediate << 10) | (source << 5) | destination


def sub_x(destination, source, immediate):
    return 0xD1000000 | (immediate << 10) | (source << 5) | destination


def subs_x(destination, source, immediate):
    return 0xF1000000 | (immediate << 10) | (source << 5) | destination


def sub_w(destination, source, immediate):
    return 0x51000000 | (immediate << 10) | (source << 5) | destination


def mov_x(destination, source):
    return 0xAA0003E0 | (source << 16) | destination


def ldr_x(destination, base, immediate=0):
    return (3 << 30) | 0x39400000 | (immediate << 10) | (base << 5) | destination

def ldr_w(destination, base, immediate=0):
    return (2 << 30) | 0x39400000 | (immediate << 10) | (base << 5) | destination


def ldr_register_offset_x(destination, base, index, *, option=3, scaled=False):
    return (
        (3 << 30)
        | 0x38200800
        | (1 << 22)
        | (index << 16)
        | (option << 13)
        | (int(scaled) << 12)
        | (base << 5)
        | destination
    )


def str_w(source, base, immediate=0):
    return (2 << 30) | 0x39000000 | (immediate << 10) | (base << 5) | source



def unscaled_access(*, size, opc, base, target, immediate, mode=0):
    return (
        (size << 30)
        | 0x38000000
        | (opc << 22)
        | ((immediate & 0x1FF) << 12)
        | (mode << 10)
        | (base << 5)
        | target
    )


def ldur_x(destination, base, immediate):
    return unscaled_access(
        size=3, opc=1, base=base, target=destination, immediate=immediate
    )


def pair_access(*, element_bytes, load, base, target, target2, immediate, mode=2):
    """Encode an integer LDP/STP pair operation for provenance tests."""
    opc = 0 if element_bytes == 4 else 2
    return (
        (opc << 30)
        | 0x28000000
        | (mode << 23)
        | (int(load) << 22)
        | ((immediate & 0x7F) << 15)
        | (target2 << 10)
        | (base << 5)
        | target
    )


def ldr_literal_x(destination, pc, target):
    displacement = target - pc
    if displacement % 4 or not -(1 << 20) <= displacement < (1 << 20):
        raise ValueError("LDR literal target out of range or unaligned")
    immediate = (displacement >> 2) & ((1 << 19) - 1)
    return 0x58000000 | (immediate << 5) | destination


class AArch64MemoryBaseProvenanceTests(unittest.TestCase):
    def test_decodes_positive_and_negative_adrp_page_targets(self):
        pc = 0x10001234
        positive = _decode_adrp(adrp(8, pc, 0x10008000), pc)
        negative = _decode_adrp(adrp(9, pc, 0x0FFF8000), pc)
        self.assertEqual(positive, (8, 0x10008000))
        self.assertEqual(negative, (9, 0x0FFF8000))
        self.assertIsNone(_decode_adrp(0xD503201F, pc))

    def test_decodes_positive_and_negative_adr_byte_targets(self):
        pc = 0x10001234
        positive = _decode_adr(adr(8, pc, pc + 0x234), pc)
        negative = _decode_adr(adr(9, pc, pc - 0x345), pc)
        self.assertEqual(positive, (8, pc + 0x234))
        self.assertEqual(negative, (9, pc - 0x345))
        self.assertIsNone(_decode_adr(0xD503201F, pc))

    def test_adr_rejects_unaligned_pc_and_address_wraparound(self):
        positive = adr(8, 0x1000, 0x1004)
        negative = adr(8, 0x1000, 0x0FFC)
        self.assertIsNone(_decode_adr(positive, 0x1001))
        self.assertIsNone(_decode_adr(positive, 0xFFFFFFFFFFFFFFFC))
        self.assertIsNone(_decode_adr(negative, 0))

    def test_tracks_adr_into_store_base_and_redacts_address(self):
        start = 0x5100
        target = 0x5488
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(adr(8, start, target), str_w(0, 8, 1)), start
        )
        access = result["memory_accesses"][0]
        self.assertEqual(access["base_provenance"], "adr_derived_address")
        self.assertEqual(access["base_definition_instruction_index"], 0)
        self.assertEqual(access["base_derivation_depth"], 1)
        self.assertNotIn(hex(target), json.dumps(result))
        self.assertFalse(result["absolute_addresses_emitted"])

    def test_tracks_adr_relocation_loaded_pointer_without_emitting_addresses(self):
        start = 0x5200
        slot = 0x5480
        target = 0xA000
        words = (adr(8, start, slot), ldr_x(9, 8), str_w(0, 9))
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, relocation_targets={slot: target}
        )
        self.assertEqual(
            result["memory_accesses"][0]["base_provenance"],
            "adr_derived_address",
        )
        self.assertEqual(
            result["memory_accesses"][1]["base_provenance"],
            "relocation_loaded_pointer",
        )
        rendered = json.dumps(result)
        self.assertNotIn(hex(slot), rendered)
        self.assertNotIn(hex(target), rendered)

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

    def test_tracks_sub_immediate_from_adr_derived_address(self):
        start = 0x5300
        target = 0x5600
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(adr(8, start, target), sub_x(9, 8, 0x20), str_w(0, 9, 1)),
            start,
        )
        access = result["memory_accesses"][0]
        self.assertEqual(access["base_provenance"], "adr_derived_address")
        self.assertEqual(access["base_definition_instruction_index"], 1)
        self.assertEqual(access["base_derivation_depth"], 2)

    def test_tracks_shifted_sub_immediate_from_adrp_address(self):
        start = 0x5400
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adrp(8, start, 0x9000),
                sub_x(9, 8, 1 << 12),
                str_w(0, 9),
            ),
            start,
        )
        access = result["memory_accesses"][0]
        self.assertEqual(access["base_provenance"], "adrp_derived_address")
        self.assertEqual(access["base_definition_instruction_index"], 1)
        self.assertEqual(access["base_derivation_depth"], 2)

    def test_tracks_sub_from_stack_pointer_as_symbolic(self):
        start = 0x5500
        words = (
            sub_x(8, 31, 0x30),
            add_x(9, 8, 0x10),
            mov_x(10, 9),
            str_w(0, 10),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start
        )
        access = result["memory_accesses"][0]
        self.assertEqual(access["base_register"], "x10")
        self.assertEqual(access["base_provenance"], "stack_pointer")
        self.assertEqual(access["base_definition_instruction_index"], 1)
        self.assertEqual(access["base_derivation_depth"], 3)

    def test_sub_underflow_invalidates_only_destination(self):
        start = 0x5600
        words = (
            adr(8, start, 0x10),
            sub_x(9, 8, 0x20),
            str_w(0, 9),
            str_w(0, 8),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start
        )
        self.assertEqual(result["memory_accesses"][0]["base_provenance"], "unknown")
        self.assertEqual(
            result["memory_accesses"][1]["base_provenance"], "adr_derived_address"
        )

    def test_subs_and_32_bit_sub_do_not_preserve_pointer_state(self):
        start = 0x5700
        prefix = (adr(8, start, start + 0x100),)
        for arithmetic in (subs_x(9, 8, 0x10), sub_w(9, 8, 0x10)):
            with self.subTest(arithmetic=hex(arithmetic)):
                result = summarize_control_flow_memory_base_provenance(
                    code_bytes(*(prefix + (arithmetic, str_w(0, 9)))),
                    start,
                )
                self.assertEqual(
                    result["memory_accesses"][0]["base_provenance"], "unknown"
                )

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

    def test_tracks_stack_pointer_derived_address_through_add_and_mov(self):
        start = 0x4100
        # ADD X8, SP, #1, LSL #12; ADD X9, X8, #0x10; MOV X10, X9.
        add_from_sp_shifted = (
            0x91000000 | (1 << 22) | (1 << 10) | (31 << 5) | 8
        )
        words = (
            add_from_sp_shifted,
            add_x(9, 8, 0x10),
            mov_x(10, 9),
            str_w(0, 10, 1),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start
        )
        access = result["memory_accesses"][0]
        self.assertEqual(access["base_register"], "x10")
        self.assertEqual(access["base_provenance"], "stack_pointer")
        self.assertEqual(access["base_definition_instruction_index"], 1)
        self.assertEqual(access["base_derivation_depth"], 3)
        self.assertEqual(result["memory_accesses_with_known_base_provenance"], 1)

    def test_stack_pointer_derived_load_never_uses_relocation_absolute_address(self):
        start = 0x4200
        words = (
            add_x(8, 31, 0x20),
            ldr_x(9, 8),
            str_w(0, 9),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start,
            relocation_targets={0x20: 0x9000},
        )
        self.assertEqual(
            result["memory_accesses"][0]["base_provenance"], "stack_pointer"
        )
        self.assertEqual(
            result["memory_accesses"][1]["base_provenance"], "unknown"
        )
        self.assertEqual(result["memory_accesses_with_known_base_provenance"], 1)

    def test_decodes_forward_and_backward_64_bit_ldr_literal(self):
        pc = 0x7000
        self.assertEqual(
            _decode_ldr_literal(ldr_literal_x(9, pc, pc + 0x100), pc),
            (9, pc + 0x100),
        )
        self.assertEqual(
            _decode_ldr_literal(ldr_literal_x(10, pc, pc - 0x80), pc),
            (10, pc - 0x80),
        )
        self.assertIsNone(_decode_ldr_literal(0x18000000, pc))  # LDR Wt literal
        self.assertIsNone(_decode_ldr_literal(0xD503201F, pc))  # NOP

    def test_ldr_literal_rejects_unaligned_pc_and_address_wraparound(self):
        pc = 0x7000
        forward = ldr_literal_x(9, pc, pc + 4)
        backward = ldr_literal_x(9, pc, pc - 4)
        self.assertIsNone(_decode_ldr_literal(forward, pc + 1))
        self.assertIsNone(_decode_ldr_literal(forward, 0xFFFFFFFFFFFFFFFC))
        self.assertIsNone(_decode_ldr_literal(backward, 0))

    def test_tracks_relocation_backed_literal_pointer_and_redacts_addresses(self):
        start = 0x7100
        slot = 0x7200
        target = 0xA000
        words = (
            ldr_literal_x(9, start, slot),
            str_w(0, 9, 3),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, relocation_targets={slot: target}
        )
        self.assertEqual(result["literal_load_count"], 1)
        self.assertEqual(result["statically_reachable_literal_load_count"], 1)
        self.assertEqual(result["relocation_backed_literal_load_count"], 1)
        self.assertEqual(
            result["literal_loads"][0],
            {
                "instruction_index": 0,
                "target_register": "x9",
                "source": "pc_relative_literal",
                "relocation_backed": True,
            },
        )
        self.assertEqual(
            result["memory_accesses"][0]["base_provenance"],
            "relocation_loaded_pointer",
        )
        rendered = json.dumps(result)
        self.assertNotIn(hex(slot), rendered)
        self.assertNotIn(hex(target), rendered)

    def test_unresolved_literal_load_clears_previous_pointer_provenance(self):
        start = 0x7300
        prior_slot = 0x7380
        prior_target = 0xA100
        unresolved_slot = 0x73A0
        words = (
            adr(9, start, prior_slot),
            ldr_literal_x(9, start + 4, unresolved_slot),
            str_w(0, 9),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, relocation_targets={prior_slot: prior_target}
        )
        self.assertFalse(result["literal_loads"][0]["relocation_backed"])
        self.assertEqual(
            result["memory_accesses"][0]["base_provenance"], "unknown"
        )

    def test_unreachable_literal_load_is_counted_but_not_interpreted(self):
        start = 0x7400
        words = (
            0x14000002,  # B to instruction 2; instruction 1 is unreachable
            ldr_literal_x(9, start + 4, start + 0x80),
            str_w(0, 9),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start
        )
        self.assertEqual(result["literal_load_count"], 1)
        self.assertEqual(result["statically_reachable_literal_load_count"], 0)
        self.assertEqual(result["statically_unreachable_literal_load_count"], 1)
        self.assertEqual(result["literal_loads"], [])
        self.assertEqual(
            result["memory_accesses"][0]["base_provenance"], "unknown"
        )

    def test_literal_load_report_obeys_observation_limit(self):
        start = 0x7500
        words = (
            ldr_literal_x(8, start, start + 0x80),
            ldr_literal_x(9, start + 4, start + 0x84),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, max_accesses=1
        )
        self.assertEqual(result["literal_load_count"], 2)
        self.assertEqual(len(result["literal_loads"]), 1)
        self.assertTrue(result["literal_loads_truncated"])

    def test_32_bit_add_from_wsp_does_not_create_pointer_provenance(self):
        start = 0x4300
        add_from_wsp = 0x11000000 | (0x20 << 10) | (31 << 5) | 8
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(add_from_wsp, str_w(0, 8)), start
        )
        self.assertEqual(result["memory_accesses"][0]["base_provenance"], "unknown")
        self.assertEqual(result["memory_accesses_with_known_base_provenance"], 0)

    def test_relocation_target_validation_detaches_caller_owned_mapping(self):
        supplied = {0x5000: 0x9000}
        snapshot = _validate_relocation_targets(supplied)

        supplied[0x5000] = 0xA000
        supplied[0x6000] = 0xB000

        self.assertEqual(snapshot, {0x5000: 0x9000})
        self.assertIs(type(snapshot), dict)
        self.assertIsNot(snapshot, supplied)

    def test_none_relocation_maps_return_independent_empty_snapshots(self):
        first = _validate_relocation_targets(None)
        second = _validate_relocation_targets(None)
        first[0x5000] = 0x9000
        self.assertEqual(second, {})

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


    def test_signed_unscaled_load_resolves_relocation_slot(self):
        start = 0x1000
        slot = 0x5038
        target = 0x9000
        words = (
            adrp(8, start, 0x5000),
            add_x(8, 8, 0x40),
            ldur_x(9, 8, -8),
            str_w(0, 9),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, relocation_targets={slot: target}
        )
        load, store = result["memory_accesses"]
        self.assertEqual(load["addressing_mode"], "unscaled")
        self.assertEqual(load["byte_offset"], -8)
        self.assertEqual(load["base_provenance"], "adrp_derived_address")
        self.assertEqual(store["base_provenance"], "relocation_loaded_pointer")
        rendered = json.dumps(result)
        self.assertNotIn(hex(slot), rendered)
        self.assertNotIn(hex(target), rendered)

    def test_pre_index_writeback_updates_known_base_provenance(self):
        start = 0x8100
        words = (
            adr(8, start, 0x9000),
            unscaled_access(
                size=2, opc=0, base=8, target=0, immediate=16, mode=3
            ),
            str_w(0, 8),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start
        )
        pre_index, after = result["memory_accesses"][0:2]
        self.assertEqual(pre_index["addressing_mode"], "pre_index")
        self.assertEqual(pre_index["byte_offset"], 16)
        self.assertEqual(pre_index["base_update_bytes"], 16)
        self.assertEqual(after["base_provenance"], "adr_derived_address")
        self.assertEqual(after["base_definition_instruction_index"], 1)
        self.assertEqual(after["base_derivation_depth"], 2)

    def test_post_index_load_uses_old_address_then_updates_base(self):
        start = 0x8200
        slot = 0x8300
        target = 0xA000
        words = (
            adr(8, start, slot),
            unscaled_access(
                size=3, opc=1, base=8, target=9, immediate=8, mode=1
            ),
            str_w(0, 8),
            str_w(0, 9),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start, relocation_targets={slot: target}
        )
        load, updated_base_store, loaded_pointer_store = result["memory_accesses"]
        self.assertEqual(load["addressing_mode"], "post_index")
        self.assertEqual(load["byte_offset"], 0)
        self.assertEqual(load["base_update_bytes"], 8)
        self.assertEqual(
            updated_base_store["base_definition_instruction_index"], 1
        )
        self.assertEqual(
            loaded_pointer_store["base_provenance"],
            "relocation_loaded_pointer",
        )


    def test_pair_load_tracks_two_relocation_backed_targets_and_post_index_base(self):
        start = 0x8300
        slot = 0x8400
        first_target = 0xA000
        second_target = 0xB000
        words = (
            adr(8, start, slot),
            pair_access(
                element_bytes=8, load=True, base=8, target=9,
                target2=10, immediate=2, mode=1,
            ),
            str_w(0, 8),
            str_w(0, 9),
            str_w(0, 10),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words),
            start,
            relocation_targets={
                slot: first_target,
                slot + 8: second_target,
            },
        )
        pair, updated_base, first_pointer, second_pointer = result["memory_accesses"]
        self.assertEqual(pair["addressing_mode"], "post_index")
        self.assertEqual(pair["access_bytes"], 16)
        self.assertEqual(pair["element_bytes"], 8)
        self.assertEqual(pair["access_count"], 2)
        self.assertEqual(pair["target_register"], "x9")
        self.assertEqual(pair["target_register2"], "x10")
        self.assertEqual(updated_base["base_definition_instruction_index"], 1)
        self.assertEqual(updated_base["base_derivation_depth"], 2)
        self.assertEqual(first_pointer["base_provenance"], "relocation_loaded_pointer")
        self.assertEqual(second_pointer["base_provenance"], "relocation_loaded_pointer")
        rendered = json.dumps(result)
        self.assertNotIn(hex(slot), rendered)
        self.assertNotIn(hex(first_target), rendered)
        self.assertNotIn(hex(second_target), rendered)

    def test_pair_load_seeds_two_exact_static_cell_value_origins(self):
        start = 0x8400
        cell = 0xA800
        words = (
            adr(8, start, cell),
            pair_access(
                element_bytes=8, load=True, base=8, target=9,
                target2=10, immediate=0, mode=2,
            ),
            str_w(0, 9),
            str_w(0, 10),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words),
            start,
            known_static_cells=(cell, cell + 8),
        )
        self.assertEqual(result["known_static_cell_full_width_load_match_count"], 2)
        self.assertEqual(result["known_static_cell_derived_base_access_count"], 2)
        self.assertTrue(
            result["memory_accesses"][1]["base_derived_from_known_static_cell"]
        )
        self.assertTrue(
            result["memory_accesses"][2]["base_derived_from_known_static_cell"]
        )
        self.assertEqual(result["memory_accesses"][0]["matches_known_static_cell"], True)

    def test_pair_store_pre_index_updates_the_base_origin(self):
        start = 0x8500
        target = 0x9000
        words = (
            adr(8, start, target),
            pair_access(
                element_bytes=8, load=False, base=8, target=9,
                target2=10, immediate=-2, mode=3,
            ),
            str_w(0, 8),
        )
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(*words), start
        )
        pair, after = result["memory_accesses"]
        self.assertEqual(pair["addressing_mode"], "pre_index")
        self.assertEqual(pair["byte_offset"], -16)
        self.assertEqual(pair["base_update_bytes"], -16)
        self.assertEqual(after["base_provenance"], "adr_derived_address")
        self.assertEqual(after["base_definition_instruction_index"], 1)
        self.assertEqual(after["base_derivation_depth"], 2)
        self.assertNotIn(hex(target), json.dumps(result))

    def test_rejected_load_writeback_alias_clears_static_cell_value_origin(self):
        for mode in (1, 3):
            with self.subTest(mode=mode):
                start = 0x90A0
                cell = 0xA800 + (mode * 0x10)
                alias_writeback = unscaled_access(
                    size=3,
                    opc=1,
                    base=8,
                    target=8,
                    immediate=8,
                    mode=mode,
                )
                result = summarize_control_flow_memory_base_provenance(
                    code_bytes(
                        adr(8, start, cell),
                        ldr_x(10, 8),
                        mov_x(8, 10),
                        alias_writeback,
                        ldr_x(9, 8),
                    ),
                    start,
                    known_static_cells=(cell,),
                )

                # The memory decoder rejects the constrained-unpredictable
                # alias-writeback form. The unknown instruction therefore
                # clears both address and loaded-value provenance.
                self.assertEqual(result["memory_access_count"], 2)
                self.assertEqual(len(result["memory_accesses"]), 2)
                later_access = result["memory_accesses"][-1]
                self.assertEqual(later_access["base_provenance"], "unknown")
                self.assertFalse(
                    later_access["base_derived_from_known_static_cell"]
                )
                self.assertEqual(
                    result["known_static_cell_derived_base_access_count"], 0
                )

    def test_marks_partial_access_to_known_static_cell_without_emitting_address(self):
        start = 0x9000
        cell = 0xA100
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(adr(8, start, cell + 4), str_w(0, 8)),
            start,
            known_static_cells=(cell,),
        )
        self.assertEqual(result["known_static_cell_match_count"], 1)
        self.assertEqual(result["known_static_cell_load_match_count"], 0)
        self.assertEqual(result["known_static_cell_store_match_count"], 1)
        self.assertTrue(result["memory_accesses"][0]["matches_known_static_cell"])
        self.assertNotIn(hex(cell), json.dumps(result))
        self.assertFalse(result["absolute_addresses_emitted"])

    def test_reports_load_and_store_matches_even_when_observations_are_truncated(self):
        start = 0x9050
        cell = 0xA300
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adr(8, start, cell),
                ldr_x(9, 8),
                str_w(9, 8),
                ldr_x(10, 8),
            ),
            start,
            max_accesses=1,
            known_static_cells=(cell,),
        )
        self.assertEqual(result["known_static_cell_match_count"], 3)
        self.assertEqual(result["known_static_cell_load_match_count"], 2)
        self.assertEqual(result["known_static_cell_store_match_count"], 1)
        self.assertEqual(len(result["memory_accesses"]), 1)
        self.assertEqual(result["memory_accesses"][0]["operation"], "load")
        self.assertTrue(result["memory_accesses_truncated"])

    def test_tracks_static_cell_loaded_value_into_later_memory_base_through_mov(self):
        start = 0x9060
        cell = 0xA400
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adr(8, start, cell),
                ldr_x(9, 8),
                mov_x(10, 9),
                ldr_x(11, 10),
            ),
            start,
            known_static_cells=(cell,),
        )
        self.assertEqual(result["known_static_cell_load_match_count"], 1)
        self.assertEqual(
            result["known_static_cell_full_width_load_match_count"], 1
        )
        self.assertEqual(
            result["known_static_cell_derived_base_access_count"], 1
        )
        later_access = result["memory_accesses"][1]
        self.assertEqual(later_access["base_provenance"], "unknown")
        self.assertTrue(later_access["base_derived_from_known_static_cell"])
        self.assertNotIn(hex(cell), json.dumps(result))

    def test_partial_or_interior_overlapping_load_does_not_seed_value_origin(self):
        start = 0x9068
        cell = 0xA480
        cases = (
            ("partial_width_at_cell_start", adr(8, start, cell), ldr_w(9, 8)),
            (
                "full_width_from_cell_interior",
                adr(8, start, cell + 4),
                ldr_x(9, 8),
            ),
        )
        for name, address_instruction, load_instruction in cases:
            with self.subTest(name=name):
                result = summarize_control_flow_memory_base_provenance(
                    code_bytes(
                        address_instruction,
                        load_instruction,
                        ldr_x(10, 9),
                    ),
                    start,
                    known_static_cells=(cell,),
                )
                self.assertEqual(result["known_static_cell_load_match_count"], 1)
                self.assertEqual(
                    result["known_static_cell_full_width_load_match_count"], 0
                )
                self.assertEqual(
                    result["known_static_cell_derived_base_access_count"], 0
                )
                self.assertFalse(
                    result["memory_accesses"][1]["base_derived_from_known_static_cell"]
                )

    def test_tracks_register_offset_access_without_guessing_dynamic_cell_overlap(self):
        start = 0x9090
        cell = 0xA700
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adr(8, start, cell),
                ldr_x(9, 8),
                ldr_register_offset_x(10, 9, 11, scaled=True),
            ),
            start,
            known_static_cells=(cell,),
        )
        self.assertEqual(result["memory_access_count"], 2)
        self.assertEqual(result["register_offset_memory_access_count"], 1)
        self.assertEqual(
            result["statically_reachable_register_offset_memory_access_count"], 1
        )
        self.assertEqual(result["known_static_cell_match_count"], 1)
        self.assertEqual(result["known_static_cell_full_width_load_match_count"], 1)
        self.assertEqual(result["known_static_cell_derived_base_access_count"], 1)
        dynamic_access = result["memory_accesses"][1]
        self.assertEqual(dynamic_access["addressing_mode"], "register_offset")
        self.assertEqual(dynamic_access["index_register"], "x11")
        self.assertEqual(dynamic_access["index_extend"], "lsl")
        self.assertEqual(dynamic_access["scale_shift"], 3)
        self.assertIsNone(dynamic_access["byte_offset"])
        self.assertIsNone(dynamic_access["matches_known_static_cell"])
        self.assertTrue(dynamic_access["base_derived_from_known_static_cell"])
        self.assertNotIn(hex(cell), json.dumps(result))

    def test_static_cell_value_origin_is_clobbered_by_calls(self):
        start = 0x9070
        cell = 0xA500
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adr(8, start, cell),
                ldr_x(9, 8),
                0x94000000,
                ldr_x(10, 9),
            ),
            start,
            known_static_cells=(cell,),
        )
        self.assertEqual(
            result["known_static_cell_derived_base_access_count"], 0
        )
        self.assertFalse(
            result["memory_accesses"][1]["base_derived_from_known_static_cell"]
        )

    def test_static_cell_derived_base_count_survives_observation_truncation(self):
        start = 0x9080
        cell = 0xA600
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adr(8, start, cell),
                ldr_x(9, 8),
                ldr_x(10, 9),
                ldr_x(11, 9),
            ),
            start,
            max_accesses=1,
            known_static_cells=(cell,),
        )
        self.assertEqual(
            result["known_static_cell_derived_base_access_count"], 2
        )
        self.assertEqual(len(result["memory_accesses"]), 1)
        self.assertTrue(result["memory_accesses_truncated"])

    def test_unrelated_and_unknown_accesses_do_not_match_known_static_cells(self):
        start = 0x9100
        cell = 0xA200
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(
                adr(8, start, cell + 8),
                str_w(0, 8),
                str_w(0, 9),
            ),
            start,
            known_static_cells=(cell,),
        )
        self.assertEqual(result["known_static_cell_match_count"], 0)
        self.assertEqual(
            [item["matches_known_static_cell"] for item in result["memory_accesses"]],
            [False, False],
        )

    def test_known_static_cell_list_is_snapshotted_before_validation(self):
        supplied = [0x1000, 0x1008]

        def mutate_caller_list(values):
            supplied.append(0x1010)
            return builtins.set(values)

        # Simulate a concurrent caller mutation between the element and
        # duplicate checks. Every validation pass must use the same snapshot.
        with patch(
            "tools.aarch64_memory_base_provenance.set",
            side_effect=mutate_caller_list,
            create=True,
        ):
            snapshot = _validate_known_static_cells(supplied)

        self.assertEqual(snapshot, (0x1000, 0x1008))
        self.assertEqual(supplied, [0x1000, 0x1008, 0x1010])

    def test_rejects_invalid_known_static_cell_lists(self):
        invalid = (
            {},
            (True,),
            (-1,),
            (0xFFFFFFFFFFFFFFF9,),
            (0x1000, 0x1000),
        )
        for cells in invalid:
            with self.subTest(cells=cells):
                with self.assertRaises(ValueError):
                    summarize_control_flow_memory_base_provenance(
                        b"", 0x1000, known_static_cells=cells
                    )

    def test_default_report_shape_is_unchanged_without_known_static_cells(self):
        result = summarize_control_flow_memory_base_provenance(
            code_bytes(str_w(0, 31)), 0x9200
        )
        self.assertNotIn("known_static_cell_match_count", result)
        self.assertNotIn("known_static_cell_load_match_count", result)
        self.assertNotIn("known_static_cell_store_match_count", result)
        self.assertNotIn("known_static_cell_full_width_load_match_count", result)
        self.assertNotIn("known_static_cell_derived_base_access_count", result)
        self.assertNotIn(
            "matches_known_static_cell", result["memory_accesses"][0]
        )
        self.assertNotIn(
            "base_derived_from_known_static_cell",
            result["memory_accesses"][0],
        )


if __name__ == "__main__":
    unittest.main()
