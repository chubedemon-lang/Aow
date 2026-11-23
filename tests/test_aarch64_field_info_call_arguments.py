"""Synthetic AArch64 vectors for FieldInfo-to-call argument provenance."""
import json
import struct
import unittest

from tools.aarch64_field_info_call_arguments import (
    _validate_method_targets,
    summarize_field_info_call_arguments,
)


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def adr(destination, pc, target):
    immediate = (target - pc) & 0x1FFFFF
    return (
        0x10000000
        | ((immediate & 0x3) << 29)
        | (((immediate >> 2) & 0x7FFFF) << 5)
        | destination
    )


def adrp(destination, pc, target):
    page_delta = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    immediate = page_delta & 0x1FFFFF
    return (
        0x90000000
        | ((immediate & 0x3) << 29)
        | (((immediate >> 2) & 0x7FFFF) << 5)
        | destination
    )


def add_x(destination, source, immediate):
    return 0x91000000 | (immediate << 10) | (source << 5) | destination


def ldr_x(destination, base, byte_offset=0):
    if byte_offset % 8:
        raise ValueError("64-bit LDR offset must be aligned")
    return (
        0xF9400000
        | ((byte_offset // 8) << 10)
        | (base << 5)
        | destination
    )


def ldr_w(destination, base, byte_offset=0):
    if byte_offset % 4:
        raise ValueError("32-bit LDR offset must be aligned")
    return (
        0xB9400000
        | ((byte_offset // 4) << 10)
        | (base << 5)
        | destination
    )


def ldp_x(destination, destination2, base):
    return (
        0xA9400000
        | (destination2 << 10)
        | (base << 5)
        | destination
    )


def mov_x(destination, source):
    return 0xAA0003E0 | (source << 16) | destination


def mov_w(destination, source):
    return 0x2A0003E0 | (source << 16) | destination


def csel_x(destination, source_n, source_m, condition=0):
    return (
        0x9A800000
        | (source_m << 16)
        | (condition << 12)
        | (source_n << 5)
        | destination
    )


def csel_w(destination, source_n, source_m, condition=0):
    return (
        0x1A800000
        | (source_m << 16)
        | (condition << 12)
        | (source_n << 5)
        | destination
    )


def ldr_literal_x(destination, pc, literal_slot):
    displacement = literal_slot - pc
    if displacement % 4:
        raise ValueError("literal slot must be word aligned")
    return (
        0x58000000
        | (((displacement // 4) & 0x7FFFF) << 5)
        | destination
    )


def bl(pc, target):
    displacement = target - pc
    if displacement % 4:
        raise ValueError("BL target must be word aligned")
    return 0x94000000 | ((displacement // 4) & 0x03FFFFFF)


def blr(register):
    return 0xD63F0000 | (register << 5)


def blraa(target_register, modifier_register):
    return 0xD73F0800 | (target_register << 5) | modifier_register


def blraaz(target_register):
    return 0xD63F081F | (target_register << 5)


def cbz_w(register, pc, target):
    displacement = target - pc
    if displacement % 4:
        raise ValueError("CBZ target must be word aligned")
    return (
        0x34000000
        | (((displacement // 4) & 0x7FFFF) << 5)
        | register
    )


def branch(pc, target):
    displacement = target - pc
    if displacement % 4:
        raise ValueError("B target must be word aligned")
    return 0x14000000 | ((displacement // 4) & 0x03FFFFFF)


class AArch64FieldInfoCallArgumentTests(unittest.TestCase):
    def setUp(self):
        self.start = 0x1000
        self.cell = 0x2000
        self.target = 0x4000
        self.label = "Example.LoginRequest::GetField/p1"
        self.targets = {self.target: [self.label]}
        self.cells = {self.cell: (7, 12, 3, 2)}

    def analyze(self, code, **kwargs):
        return summarize_field_info_call_arguments(
            code,
            self.start,
            self.targets,
            self.cells,
            **kwargs,
        )

    def test_method_target_validation_detaches_mapping_and_label_lists(self):
        supplied = {self.target: [self.label]}
        snapshot = _validate_method_targets(supplied)

        supplied[self.target][0] = "Other.Type::Changed/p1"
        supplied[self.target] = ["Other.Type::Replacement/p0"]
        supplied[0x5000] = ["Other.Type::Added/p0"]

        self.assertEqual(snapshot, {self.target: (self.label,)})
        self.assertIs(type(snapshot), dict)
        self.assertIs(type(snapshot[self.target]), tuple)

    def test_traces_exact_static_cell_load_through_mov_to_argument(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            mov_x(0, 2),
            bl(self.start + 12, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["unattributed_direct_call_count"], 0)
        self.assertEqual(result["ambiguous_target_direct_call_count"], 0)
        self.assertEqual(result["callsite_count"], 1)
        observation = result["callsite_observations"][0]
        self.assertEqual(observation["instruction_index"], 3)
        self.assertEqual(observation["target_method"], "Example.LoginRequest::GetField")
        expected_reference = {
            "usage_occurrence_position": 7,
            "field_ref_index": 12,
            "type_index": 3,
            "field_index_within_type": 2,
        }
        self.assertEqual(observation["field_info_arguments"], {
            "x0": expected_reference,
            "x2": expected_reference,
        })

    def test_traces_adrp_add_address_formation(self):
        cell = 0x2A18
        code = words(
            adrp(1, self.start, cell),
            add_x(1, 1, cell & 0xFFF),
            ldr_x(2, 1),
            mov_x(0, 2),
            bl(self.start + 16, self.target),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            self.targets,
            {cell: (0, 4, 9, 1)},
        )
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(
            result["callsite_observations"][0]["field_info_arguments"]["x0"]["field_ref_index"],
            4,
        )

    def test_traces_relocation_backed_literal_address(self):
        literal_slot = 0x1800
        code = words(
            ldr_literal_x(1, self.start, literal_slot),
            ldr_x(2, 1),
            mov_x(0, 2),
            bl(self.start + 12, self.target),
        )
        result = self.analyze(
            code,
            relocation_targets={literal_slot: self.cell},
        )
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(
            result["callsite_observations"][0]["field_info_arguments"]["x0"]["type_index"],
            3,
        )

    def test_traces_two_adjacent_field_info_cells_from_pair_load(self):
        second_cell = self.cell + 8
        code = words(
            adr(3, self.start, self.cell),
            ldp_x(0, 2, 3),
            bl(self.start + 8, self.target),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            self.targets,
            {
                self.cell: (0, 1, 2, 3),
                second_cell: (1, 4, 5, 6),
            },
        )
        arguments = result["callsite_observations"][0]["field_info_arguments"]
        self.assertEqual(arguments["x0"]["field_ref_index"], 1)
        self.assertEqual(arguments["x2"]["field_ref_index"], 4)

    def test_32_bit_mov_is_counted_as_truncated_not_exact_field_info(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(8, 1),
            mov_w(0, 8),
            bl(self.start + 12, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_argument_direct_call_count"], 0)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 1)
        self.assertEqual(result["callsite_count"], 0)
        self.assertEqual(result["callsite_observations"], [])

    def test_64_bit_mov_does_not_restore_truncated_field_info_value(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(8, 1),
            mov_w(0, 8),
            mov_x(3, 0),
            bl(self.start + 16, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_argument_direct_call_count"], 0)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 1)
        self.assertEqual(result["callsite_count"], 0)

    def test_overwrite_clears_truncated_field_info_provenance(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(8, 1),
            mov_w(0, 8),
            adr(0, self.start + 12, self.cell + 0x100),
            bl(self.start + 16, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 0)

    def test_unknown_instruction_counts_exact_and_truncated_field_info_drops(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(8, 1),
            mov_w(0, 8),
            0xCA030042,  # EOR X2, X2, X3: unsupported by this bounded pass.
            bl(self.start + 16, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["unknown_instruction_field_info_drop_count"], 1)
        self.assertEqual(
            result["unknown_instruction_exact_field_info_register_drop_count"], 1
        )
        self.assertEqual(
            result["unknown_instruction_truncated_field_info_register_drop_count"], 1
        )
        self.assertEqual(result["field_info_argument_direct_call_count"], 0)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 0)
        self.assertEqual(result["callsite_count"], 0)

    def test_unknown_instruction_without_field_info_state_is_not_counted(self):
        code = words(
            0xCA030042,  # EOR X2, X2, X3.
            bl(self.start + 4, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["unknown_instruction_field_info_drop_count"], 0)
        self.assertEqual(
            result["unknown_instruction_exact_field_info_register_drop_count"], 0
        )
        self.assertEqual(
            result["unknown_instruction_truncated_field_info_register_drop_count"], 0
        )

    def test_indirect_blr_counts_exact_field_info_argument_without_attribution(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            blr(9),
        )
        result = self.analyze(code)
        self.assertEqual(result["indirect_call_instruction_count"], 1)
        self.assertEqual(result["statically_reachable_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 1)
        self.assertEqual(result["field_info_truncated_argument_indirect_call_count"], 0)
        self.assertEqual(result["field_info_argument_direct_call_count"], 0)
        self.assertEqual(result["callsite_count"], 0)
        self.assertEqual(result["callsite_observations"], [])

    def test_indirect_call_target_register_is_not_counted_as_an_argument(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            blr(0),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 0)
        self.assertEqual(result["callsite_count"], 0)

    def test_authenticated_call_excludes_target_and_modifier_registers(self):
        second_cell = self.cell + 8
        third_cell = self.cell + 16
        code = words(
            adr(3, self.start, self.cell),
            ldr_x(0, 3),
            adr(4, self.start + 8, second_cell),
            ldr_x(1, 4),
            adr(5, self.start + 16, third_cell),
            ldr_x(2, 5),
            blraa(1, 2),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            self.targets,
            {
                self.cell: (0, 1, 2, 3),
                second_cell: (1, 4, 5, 6),
                third_cell: (2, 7, 8, 9),
            },
        )
        self.assertEqual(result["field_info_argument_indirect_call_count"], 1)
        self.assertEqual(result["statically_reachable_indirect_call_count"], 1)
        self.assertEqual(result["callsite_count"], 0)

    def test_zero_modifier_authenticated_target_is_not_counted_as_argument(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            blraaz(0),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 0)
        self.assertEqual(result["callsite_count"], 0)

    def test_truncated_field_info_at_indirect_call_is_counted_separately(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(8, 1),
            mov_w(0, 8),
            blr(9),
        )
        result = self.analyze(code)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 0)
        self.assertEqual(result["field_info_truncated_argument_indirect_call_count"], 1)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 0)
        self.assertEqual(result["callsite_count"], 0)

    def test_resolves_blr_target_from_relocation_backed_literal_and_reports_field_info(self):
        literal_slot = 0x1800
        code = words(
            ldr_literal_x(9, self.start, literal_slot),
            adr(1, self.start + 4, self.cell),
            ldr_x(0, 1),
            blr(9),
        )
        result = self.analyze(
            code,
            relocation_targets={literal_slot: self.target},
        )
        self.assertEqual(result["resolved_indirect_call_count"], 1)
        self.assertEqual(result["unresolved_indirect_call_count"], 0)
        self.assertEqual(result["ambiguous_indirect_call_count"], 0)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_resolved_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_unattributed_indirect_call_count"], 0)
        self.assertEqual(result["indirect_call_observation_count"], 1)
        observation = result["indirect_call_observations"][0]
        self.assertEqual(observation["linear_window_indirect_call_ordinal"], 0)
        self.assertEqual(observation["instruction_index"], 3)
        self.assertEqual(observation["target_method"], "Example.LoginRequest::GetField")
        self.assertEqual(
            observation["field_info_arguments"]["x0"],
            {
                "usage_occurrence_position": 7,
                "field_ref_index": 12,
                "type_index": 3,
                "field_index_within_type": 2,
            },
        )
        rendered = json.dumps(result)
        self.assertNotIn(hex(literal_slot), rendered)
        self.assertNotIn(hex(self.target), rendered)
        self.assertNotIn(code.hex(), rendered)

    def test_resolves_blr_target_through_relocation_backed_pointer_slot_load(self):
        pointer_slot = 0x2800
        code = words(
            adrp(9, self.start, pointer_slot),
            add_x(9, 9, pointer_slot & 0xFFF),
            ldr_x(9, 9),
            adr(1, self.start + 12, self.cell),
            ldr_x(0, 1),
            blr(9),
        )
        result = self.analyze(
            code,
            relocation_targets={pointer_slot: self.target},
        )
        self.assertEqual(result["resolved_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_resolved_indirect_call_count"], 1)
        self.assertEqual(
            result["indirect_call_observations"][0]["target_method"],
            "Example.LoginRequest::GetField",
        )

    def test_authenticated_indirect_target_resolution_excludes_target_and_modifier(self):
        literal_slot = 0x1800
        second_cell = self.cell + 8
        code = words(
            ldr_literal_x(9, self.start, literal_slot),
            adr(1, self.start + 4, self.cell),
            ldr_x(0, 1),
            adr(2, self.start + 12, second_cell),
            ldr_x(10, 2),
            blraa(9, 10),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            self.targets,
            {
                self.cell: (7, 12, 3, 2),
                second_cell: (8, 13, 4, 1),
            },
            relocation_targets={literal_slot: self.target},
        )
        self.assertEqual(result["resolved_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_resolved_indirect_call_count"], 1)
        arguments = result["indirect_call_observations"][0]["field_info_arguments"]
        self.assertEqual(set(arguments), {"x0"})
        self.assertNotIn("x10", arguments)

    def test_zero_modifier_authenticated_call_can_resolve_relocated_target(self):
        literal_slot = 0x1800
        code = words(
            ldr_literal_x(9, self.start, literal_slot),
            adr(1, self.start + 4, self.cell),
            ldr_x(0, 1),
            blraaz(9),
        )
        result = self.analyze(
            code,
            relocation_targets={literal_slot: self.target},
        )
        self.assertEqual(result["resolved_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_resolved_indirect_call_count"], 1)
        self.assertEqual(result["indirect_call_observation_count"], 1)

    def test_unresolved_indirect_target_with_field_info_is_not_attributed(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            blr(9),
        )
        result = self.analyze(code)
        self.assertEqual(result["resolved_indirect_call_count"], 0)
        self.assertEqual(result["unresolved_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_unattributed_indirect_call_count"], 1)
        self.assertEqual(result["indirect_call_observations"], [])

    def test_ambiguous_indirect_target_with_field_info_is_not_attributed(self):
        literal_slot = 0x1800
        code = words(
            ldr_literal_x(9, self.start, literal_slot),
            adr(1, self.start + 4, self.cell),
            ldr_x(0, 1),
            blr(9),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            {
                self.target: [self.label, "Other.Type::Different/p1"],
            },
            self.cells,
            relocation_targets={literal_slot: self.target},
        )
        self.assertEqual(result["resolved_indirect_call_count"], 0)
        self.assertEqual(result["ambiguous_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_unattributed_indirect_call_count"], 1)
        self.assertEqual(result["indirect_call_observations"], [])

    def test_csel_preserves_same_fieldref_from_both_inputs(self):
        second_cell = self.cell + 8
        self.cells[second_cell] = self.cells[self.cell]
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            adr(3, self.start + 8, second_cell),
            ldr_x(4, 3),
            csel_x(5, 2, 4, condition=1),
            mov_x(0, 5),
            bl(self.start + 24, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["conditional_select_field_info_merge_drop_count"], 0)
        self.assertEqual(
            result["callsite_observations"][0]["field_info_arguments"]["x0"],
            {
                "usage_occurrence_position": 7,
                "field_ref_index": 12,
                "type_index": 3,
                "field_index_within_type": 2,
            },
        )

    def test_csel_drops_different_fieldref_coordinates(self):
        second_cell = self.cell + 8
        self.cells[second_cell] = (8, 13, 3, 4)
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            adr(3, self.start + 8, second_cell),
            ldr_x(4, 3),
            csel_x(5, 2, 4),
            mov_x(0, 5),
            bl(self.start + 24, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["conditional_select_field_info_merge_drop_count"], 1)
        self.assertEqual(
            result["conditional_select_exact_source_register_unmerged_count"], 2
        )
        arguments = result["callsite_observations"][0]["field_info_arguments"]
        self.assertNotIn("x0", arguments)
        self.assertNotIn("x5", arguments)

    def test_csel_w_marks_same_fieldref_as_truncated(self):
        second_cell = self.cell + 8
        self.cells[second_cell] = self.cells[self.cell]
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            adr(3, self.start + 8, second_cell),
            ldr_x(4, 3),
            csel_w(5, 2, 4),
            mov_x(0, 5),
            bl(self.start + 24, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 1)
        self.assertEqual(result["conditional_select_field_info_merge_drop_count"], 0)
        self.assertNotIn(
            "x0", result["callsite_observations"][0]["field_info_arguments"]
        )

    def test_csel_drops_fieldref_when_other_input_has_no_provenance(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            mov_x(4, 31),
            csel_x(5, 2, 4),
            mov_x(0, 5),
            bl(self.start + 20, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(result["conditional_select_field_info_merge_drop_count"], 1)
        self.assertEqual(
            result["conditional_select_exact_source_register_unmerged_count"], 1
        )
        arguments = result["callsite_observations"][0]["field_info_arguments"]
        self.assertNotIn("x0", arguments)
        self.assertNotIn("x5", arguments)

    def test_csel_does_not_promote_truncated_input_to_exact(self):
        second_cell = self.cell + 8
        self.cells[second_cell] = self.cells[self.cell]
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            mov_w(4, 2),
            csel_x(5, 2, 4),
            mov_x(0, 5),
            bl(self.start + 20, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["field_info_truncated_argument_direct_call_count"], 1)
        self.assertEqual(result["conditional_select_field_info_merge_drop_count"], 0)
        self.assertNotIn(
            "x0", result["callsite_observations"][0]["field_info_arguments"]
        )

    def test_csel_preserves_equal_relocation_backed_indirect_target(self):
        literal_slot = 0x1800
        pointer_slot = 0x1810
        code = words(
            ldr_literal_x(9, self.start, literal_slot),
            adr(1, self.start + 4, pointer_slot),
            ldr_x(10, 1),
            adr(3, self.start + 12, self.cell),
            ldr_x(0, 3),
            csel_x(11, 9, 10, condition=2),
            blr(11),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            self.targets,
            self.cells,
            relocation_targets={
                literal_slot: self.target,
                pointer_slot: self.target,
            },
        )
        self.assertEqual(result["resolved_indirect_call_count"], 1)
        self.assertEqual(result["field_info_argument_resolved_indirect_call_count"], 1)
        self.assertEqual(result["indirect_call_observations"][0]["target_method"],
                         "Example.LoginRequest::GetField")

    def test_32_bit_load_does_not_match_eight_byte_usage_cell(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_w(2, 1),
            mov_x(0, 2),
            bl(self.start + 12, self.target),
        )
        self.assertEqual(self.analyze(code)["callsite_count"], 0)

    def test_unknown_instruction_drops_field_provenance(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            0xFFFFFFFF,
            mov_x(0, 2),
            bl(self.start + 16, self.target),
        )
        self.assertEqual(self.analyze(code)["callsite_count"], 0)

    def test_call_clobbers_field_argument_before_later_call(self):
        other_target = 0x5000
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            bl(self.start + 8, self.target),
            bl(self.start + 12, other_target),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            {
                self.target: [self.label],
                other_target: ["Example.LoginRequest::Continue/p0"],
            },
            self.cells,
        )
        self.assertEqual(result["callsite_count"], 1)
        self.assertEqual(
            result["callsite_observations"][0]["target_method"],
            "Example.LoginRequest::GetField",
        )

    def test_unresolved_direct_target_is_counted_but_not_attributed(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            bl(self.start + 8, self.target),
        )
        result = summarize_field_info_call_arguments(
            code, self.start, {}, self.cells
        )
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["unattributed_direct_call_count"], 1)
        self.assertEqual(result["ambiguous_target_direct_call_count"], 0)
        self.assertEqual(result["callsite_count"], 0)
        self.assertEqual(result["callsite_observations"], [])

    def test_ambiguous_direct_target_is_counted_but_not_attributed(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            bl(self.start + 8, self.target),
        )
        result = summarize_field_info_call_arguments(
            code,
            self.start,
            {self.target: [self.label, "Other.Type::Different/p1"]},
            self.cells,
        )
        self.assertEqual(result["field_info_argument_direct_call_count"], 1)
        self.assertEqual(result["unattributed_direct_call_count"], 1)
        self.assertEqual(result["ambiguous_target_direct_call_count"], 1)
        self.assertEqual(result["callsite_count"], 0)
        self.assertEqual(result["callsite_observations"], [])

    def test_two_predecessor_join_drops_field_provenance(self):
        code = words(
            adr(1, self.start, self.cell),
            cbz_w(3, self.start + 4, self.start + 16),
            ldr_x(2, 1),
            branch(self.start + 12, self.start + 20),
            0xD503201F,
            mov_x(0, 2),
            bl(self.start + 24, self.target),
        )
        self.assertEqual(self.analyze(code)["callsite_count"], 0)

    def test_report_never_emits_native_addresses_or_bytes(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(0, 1),
            bl(self.start + 8, self.target),
        )
        result = self.analyze(code)
        rendered = json.dumps(result)
        self.assertNotIn(hex(self.cell), rendered)
        self.assertNotIn(hex(self.target), rendered)
        self.assertNotIn(code.hex(), rendered)
        self.assertFalse(result["absolute_addresses_emitted"])
        self.assertFalse(result["raw_instructions_emitted"])

    def test_rejects_hostile_and_malformed_inputs(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("bytes subclass hook must not run")

        class HostileDict(dict):
            def items(self):
                raise AssertionError("dict subclass hook must not run")

        class HostileTuple(tuple):
            pass

        valid = words(0xD503201F)
        with self.assertRaisesRegex(ValueError, "exact bytes"):
            self.analyze(HostileBytes(valid))
        with self.assertRaisesRegex(ValueError, "exact dict"):
            summarize_field_info_call_arguments(
                valid, self.start, self.targets, HostileDict(self.cells)
            )
        with self.assertRaisesRegex(ValueError, "exact four-integer tuples"):
            summarize_field_info_call_arguments(
                valid, self.start, self.targets,
                {self.cell: HostileTuple((0, 1, 2, 3))},
            )
        with self.assertRaisesRegex(ValueError, "aligned"):
            summarize_field_info_call_arguments(
                valid, self.start + 1, self.targets, self.cells
            )


if __name__ == "__main__":
    unittest.main()
