"""Synthetic tests for redacted AArch64 small-argument observations."""
import struct
import unittest

from tools.aarch64_call_argument_evidence import (
    _decode_move_wide,
    _decode_conditional_branch_target,
    _decode_unconditional_branch_target,
    _is_indirect_branch,
    _is_indirect_call,
    summarize_small_argument_constants,
)


def movz_x(register, immediate, shift=0):
    return 0xD2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movk_x(register, immediate, shift=0):
    return 0xF2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movz_w(register, immediate, shift=0):
    return 0x52800000 | ((shift // 16) << 21) | (immediate << 5) | register


def mov_x(destination, source):
    return 0xAA0003E0 | (source << 16) | destination


def mov_w(destination, source):
    return 0x2A0003E0 | (source << 16) | destination


def add_x(register, source, immediate):
    return 0x91000000 | (immediate << 10) | (source << 5) | register


def bl(pc, target):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x94000000 | ((delta >> 2) & 0x03FFFFFF)


def b(pc, target):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x14000000 | ((delta // 4) & 0x03FFFFFF)


def b_cond(pc, target, condition=0):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x54000000 | (((delta // 4) & 0x7FFFF) << 5) | condition


def cbz(pc, target, register=0):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x34000000 | (((delta // 4) & 0x7FFFF) << 5) | register


def tbz(pc, target, register=0, bit=0):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return (
        0x36000000 | (((delta // 4) & 0x3FFF) << 5)
        | ((bit & 0x20) << 26) | ((bit & 0x1F) << 19) | register
    )


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


class Aarch64CallArgumentEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.target = 0x4000
        self.label = "com.geargames.common.utils.ClientNetworkStreamBuffer::SetDataAvailable/p1"
        self.targets = {self.target: [self.label]}
        self.prefixes = ("ClientNetworkStreamBuffer::SetDataAvailable",)

    def test_reports_small_constant_in_x1_before_allowlisted_call(self):
        code = words(movz_x(1, 4), bl(0x1004, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [{
            "linear_window_call_ordinal": 0,
            "control_flow_block_index": 0,
            "instruction_index": 1,
            "target_method": "com.geargames.common.utils.ClientNetworkStreamBuffer::SetDataAvailable",
            "known_small_argument_constants": {"x1": 4},
        }])

    def test_tracks_add_immediate(self):
        code = words(movz_x(1, 3), add_x(1, 1, 1), bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 4})

    def test_tracks_movk_and_omits_values_above_public_limit(self):
        code = words(
            movz_x(1, 1), movk_x(1, 2, 16), bl(0x100C, self.target)
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_redacted_argument_classes_cover_wide_constants_without_values(self):
        code = words(
            movz_x(0, 0),
            movz_x(1, 4),
            movz_x(2, 0x5450),
            movk_x(2, 0x4854, 16),
            movz_x(3, 1, 32),
            movz_x(4, 0x1234),
            bl(0x1018, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes,
            include_argument_classes=True,
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["known_small_argument_constants"],
            {"x0": 0, "x1": 4, "x4": 0x1234},
        )
        self.assertEqual(
            result[0]["known_argument_constant_classes"],
            {
                "x0": "zero",
                "x1": "small_nonzero_16bit",
                "x2": "nonzero_32bit",
                "x3": "nonzero_64bit",
                "x4": "small_nonzero_16bit",
            },
        )
        self.assertNotIn("0x48545450", repr(result))
        self.assertNotIn(0x48545450, result[0]["known_small_argument_constants"].values())

    def test_wide_constants_remain_silent_without_explicit_class_mode(self):
        code = words(
            movz_x(1, 0x5450),
            movk_x(1, 0x4854, 16),
            bl(0x1008, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_argument_class_option_requires_boolean(self):
        for invalid in (None, 0, 1, "yes"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                summarize_small_argument_constants(
                    b"", 0x1000, self.targets,
                    target_prefixes=self.prefixes,
                    include_argument_classes=invalid,
                )

    def test_tracks_zero_extending_w_register_move(self):
        code = words(movz_w(1, 4), bl(0x1004, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 4})

    def test_unknown_instruction_clears_register_state(self):
        code = words(movz_x(1, 4), 0x8B010000, bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_unconditional_branch_preserves_state_on_unique_forward_successor(self):
        code = words(movz_x(1, 4), b(0x1004, 0x1008), bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 4})
        self.assertEqual(result[0]["control_flow_block_index"], 1)

    def test_call_clobbers_caller_saved_argument_registers(self):
        second = self.target + 4
        targets = {self.target: [self.label], second: [self.label]}
        code = words(movz_x(1, 4), bl(0x1004, self.target), bl(0x1008, second))
        result = summarize_small_argument_constants(
            code, 0x1000, targets, target_prefixes=self.prefixes
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 4})

    def test_ignores_ambiguous_and_non_allowlisted_targets(self):
        ambiguous = self.target + 4
        other = self.target + 8
        targets = {
            self.target: [self.label, self.label + "Other"],
            ambiguous: ["com.example.Other::Write/p1"],
            other: [self.label],
        }
        code = words(
            movz_x(1, 4),
            bl(0x1004, self.target),
            movz_x(1, 5),
            bl(0x100C, ambiguous),
            movz_x(1, 6),
            bl(0x1014, other),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, targets, target_prefixes=self.prefixes
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 6})

    def test_rejects_malformed_windows_and_invalid_prefixes(self):
        for code, start in ((b"abc", 0x1000), (b"\x00" * 4, 0x1002)):
            with self.subTest(code=code, start=start), self.assertRaises(ValueError):
                summarize_small_argument_constants(
                    code, start, self.targets, target_prefixes=self.prefixes
                )
        with self.assertRaises(ValueError):
            summarize_small_argument_constants(
                b"", 0x1000, self.targets, target_prefixes=()
            )

    def test_tracks_unshifted_x_register_move_alias(self):
        code = words(movz_x(2, 4), mov_x(1, 2), bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"]["x1"], 4)

    def test_tracks_w_register_move_with_zero_extension(self):
        code = words(movz_x(2, 1, 32), mov_w(1, 2), bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 0})

    def test_move_from_zero_register_produces_zero(self):
        code = words(mov_x(1, 31), bl(0x1004, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 0})

    def test_move_to_zero_register_does_not_clobber_other_constants(self):
        code = words(movz_x(1, 4), mov_x(31, 2), bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"]["x1"], 4)

    def test_shifted_orr_is_not_misclassified_as_mov_alias(self):
        shifted_orr = 0xAA0007E0 | (2 << 16) | 1
        code = words(movz_x(1, 4), shifted_orr, bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_move_wide_decoder_rejects_invalid_register_and_shift(self):
        self.assertIsNone(_decode_move_wide(0xD280003F))  # XZR destination
        invalid_w_shift = movz_w(1, 4, 32)
        self.assertIsNone(_decode_move_wide(invalid_w_shift))


    def test_conditional_branch_decoder_handles_b_cond_cbz_and_tbz(self):
        start = 0x5000
        self.assertEqual(
            _decode_conditional_branch_target(
                b_cond(start, start + 12), start
            ),
            start + 12,
        )
        self.assertEqual(
            _decode_conditional_branch_target(
                cbz(start, start + 8), start
            ),
            start + 8,
        )
        self.assertEqual(
            _decode_conditional_branch_target(
                tbz(start, start - 8), start
            ),
            start - 8,
        )
        self.assertEqual(
            _decode_unconditional_branch_target(
                b(start, start + 16), start
            ),
            start + 16,
        )
        self.assertIsNone(
            _decode_conditional_branch_target(0xD65F03C0, start)
        )

    def test_conditional_paths_keep_constants_when_they_do_not_join(self):
        code = words(
            movz_x(1, 4),
            b_cond(0x1004, 0x1010),
            bl(0x1008, self.target),
            0xD65F03C0,  # ret
            bl(0x1010, self.target),
            0xD65F03C0,  # ret
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(len(result), 2)
        self.assertEqual(
            [item["known_small_argument_constants"] for item in result],
            [{"x1": 4}, {"x1": 4}],
        )
        self.assertNotEqual(
            result[0]["control_flow_block_index"],
            result[1]["control_flow_block_index"],
        )

    def test_join_drops_constants_that_are_not_common_to_all_predecessors(self):
        code = words(
            b_cond(0x1000, 0x1010),
            movz_x(1, 4),
            b(0x1008, 0x1014),
            0xD503201F,  # unreachable fallthrough after B
            movz_x(1, 5),
            bl(0x1014, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_unconditional_branch_skips_unreachable_fallthrough_bytes(self):
        code = words(
            b(0x1000, 0x100C),
            movz_x(1, 4),
            bl(0x1008, self.target),
            bl(0x100C, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_return_and_indirect_branch_terminate_the_bounded_path(self):
        for terminator in (0xD65F03C0, 0xD61F0000):
            with self.subTest(terminator=terminator):
                code = words(
                    movz_x(1, 4),
                    terminator,
                    bl(0x1008, self.target),
                )
                result = summarize_small_argument_constants(
                    code, 0x1000, self.targets, target_prefixes=self.prefixes
                )
                self.assertEqual(result, [])

    def test_indirect_call_clobbers_argument_register_constants(self):
        code = words(
            movz_x(1, 4),
            0xD63F0000,  # blr x0
            bl(0x1008, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_conditional_branch_outside_window_keeps_fallthrough_path(self):
        code = words(
            movz_x(1, 4),
            b_cond(0x1004, 0x2000),
            bl(0x1008, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 4})

    def test_backedge_does_not_import_constants_into_loop_header(self):
        code = words(
            b_cond(0x1000, 0x1008),
            movz_x(1, 4),
            bl(0x1008, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_rejects_code_windows_above_analysis_limit(self):
        with self.assertRaisesRegex(ValueError, "64 KiB"):
            summarize_small_argument_constants(
                b"\0" * (64 * 1024 + 4), 0x1000,
                self.targets, target_prefixes=self.prefixes
            )


    def test_pointer_authenticated_branches_and_returns_terminate_cfg(self):
        terminators = (
            0xD71F0801,  # braa x0, x1
            0xD71F0C01,  # brab x0, x1
            0xD61F081F,  # braaz x0
            0xD61F0C1F,  # brabz x0
            0xD65F0BFF,  # retaa
            0xD65F0FFF,  # retab
            0xD69F03E0,  # eret
            0xD69F0BFF,  # eretaa
            0xD69F0FFF,  # eretab
            0xD6BF03E0,  # drps
        )
        for terminator in terminators:
            with self.subTest(terminator=hex(terminator)):
                code = words(
                    movz_x(1, 4),
                    terminator,
                    bl(0x1008, self.target),
                )
                result = summarize_small_argument_constants(
                    code, 0x1000, self.targets, target_prefixes=self.prefixes
                )
                self.assertEqual(result, [])

    def test_pointer_authenticated_indirect_calls_clobber_caller_saved_state(self):
        calls = (
            0xD73F0801,  # blraa x0, x1
            0xD73F0C01,  # blrab x0, x1
            0xD63F081F,  # blraaz x0
            0xD63F0C1F,  # blrabz x0
        )
        for call in calls:
            with self.subTest(call=hex(call)):
                code = words(
                    movz_x(1, 4),
                    call,
                    bl(0x1008, self.target),
                )
                result = summarize_small_argument_constants(
                    code, 0x1000, self.targets, target_prefixes=self.prefixes
                )
                self.assertEqual(result, [])

    def test_pointer_authenticated_indirect_call_keeps_return_fallthrough(self):
        code = words(
            0xD73F0801,  # blraa x0, x1
            movz_x(1, 7),
            bl(0x1008, self.target),
        )
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(
            result[0]["known_small_argument_constants"], {"x1": 7}
        )


    def test_authenticated_branch_masks_reject_near_miss_encodings(self):
        near_misses = (
            0xD71F1801,  # altered fixed opcode bits in BRAA/BRAB family
            0xD61F081E,  # invalid fixed low bits near BRAAZ
            0xD61F0C1E,  # invalid fixed low bits near BRABZ
            0xD65F0BFE,  # RETAA near miss
            0xD65F0FFE,  # RETAB near miss
            0xD69F03E1,  # ERET near miss
            0xD69F0BFE,  # ERETAA near miss
            0xD69F0FFE,  # ERETAB near miss
            0xD6BF03E1,  # DRPS near miss
        )
        for word in near_misses:
            with self.subTest(word=hex(word)):
                self.assertFalse(_is_indirect_branch(word))

    def test_authenticated_call_masks_reject_near_miss_encodings(self):
        near_misses = (
            0xD73F1801,  # altered fixed opcode bits in BLRAA/BLRAB family
            0xD63F081E,  # invalid fixed low bits near BLRAAZ
            0xD63F0C1E,  # invalid fixed low bits near BLRABZ
        )
        for word in near_misses:
            with self.subTest(word=hex(word)):
                self.assertFalse(_is_indirect_call(word))

    def test_indirect_control_flow_recognizers_reject_non_word_inputs(self):
        invalid_values = (None, True, -1, 0x1_0000_0000, 1.0, "0xD71F0801")
        for value in invalid_values:
            with self.subTest(value=repr(value)):
                self.assertFalse(_is_indirect_branch(value))
                self.assertFalse(_is_indirect_call(value))


if __name__ == "__main__":
    unittest.main()
