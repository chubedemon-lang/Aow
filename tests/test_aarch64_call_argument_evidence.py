"""Synthetic tests for redacted AArch64 small-argument observations."""
import struct
import unittest

from tools.aarch64_call_argument_evidence import (
    _decode_move_wide,
    summarize_small_argument_constants,
)


def movz_x(register, immediate, shift=0):
    return 0xD2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movk_x(register, immediate, shift=0):
    return 0xF2800000 | ((shift // 16) << 21) | (immediate << 5) | register


def movz_w(register, immediate, shift=0):
    return 0x52800000 | ((shift // 16) << 21) | (immediate << 5) | register


def add_x(register, source, immediate):
    return 0x91000000 | (immediate << 10) | (source << 5) | register


def bl(pc, target):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x94000000 | ((delta >> 2) & 0x03FFFFFF)


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

    def test_tracks_zero_extending_w_register_move(self):
        code = words(movz_w(1, 4), bl(0x1004, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result[0]["known_small_argument_constants"], {"x1": 4})

    def test_unknown_instruction_clears_register_state(self):
        code = words(movz_x(1, 4), 0xAA0003E0, bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

    def test_unconditional_branch_clears_register_state(self):
        code = words(movz_x(1, 4), 0x14000001, bl(0x1008, self.target))
        result = summarize_small_argument_constants(
            code, 0x1000, self.targets, target_prefixes=self.prefixes
        )
        self.assertEqual(result, [])

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

    def test_move_wide_decoder_rejects_invalid_register_and_shift(self):
        self.assertIsNone(_decode_move_wide(0xD280003F))  # XZR destination
        invalid_w_shift = movz_w(1, 4, 32)
        self.assertIsNone(_decode_move_wide(invalid_w_shift))


if __name__ == "__main__":
    unittest.main()
