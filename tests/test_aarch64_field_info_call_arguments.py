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

    def test_32_bit_mov_preserves_encoded_field_info_token_provenance(self):
        code = words(
            adr(1, self.start, self.cell),
            ldr_x(2, 1),
            mov_w(0, 2),
            bl(self.start + 12, self.target),
        )
        result = self.analyze(code)
        self.assertEqual(result["callsite_count"], 1)
        self.assertIn("x0", result["callsite_observations"][0]["field_info_arguments"])

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
