"""Synthetic tests for immediate AArch64 call-result zero/bit-test evidence."""
import struct
import unittest

from tools.aarch64_call_return_evidence import (
    _decode_b_cond_eq_ne,
    _decode_cbz_cbnz_on_x0,
    _decode_cmp_zero_on_x0,
    _decode_tbz_tbnz_on_x0,
    summarize_immediate_call_result_zero_tests,
)


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def bl():
    return 0x94000001


def blr(register=8):
    return 0xD63F0000 | (register << 5)


def cbz_w0(delta):
    return 0x34000000 | ((delta & 0x7FFFF) << 5)


def cbnz_x0(delta):
    return 0xB5000000 | ((delta & 0x7FFFF) << 5)


def tbz_w0(bit, delta):
    return 0x36000000 | ((delta & 0x3FFF) << 5) | ((bit & 0x1F) << 19)


def tbnz_x0(bit, delta):
    return (
        0xB7000000
        | ((delta & 0x3FFF) << 5)
        | ((bit & 0x1F) << 19)
    )


def b_cond(condition, delta):
    return 0x54000000 | ((delta & 0x7FFFF) << 5) | condition


class ImmediateCallReturnEvidenceTests(unittest.TestCase):
    def test_direct_call_followed_by_cbz_w0_is_reported_with_relative_target(self):
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), cbz_w0(2), 0xD503201F, 0xD65F03C0)
        )
        self.assertEqual(report["recognized_call_count"], 1)
        self.assertEqual(report["immediate_w0_x0_zero_test_count"], 1)
        self.assertEqual(report["observations"][0], {
            "call_instruction_index": 0,
            "branch_instruction_index": 1,
            "call_kind": "direct_bl",
            "tested_register": "w0",
            "branch_when": "zero",
            "branch_target_delta_instructions": 2,
            "branch_target_within_window": True,
            "branch_target_instruction_index": 3,
        })
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])

    def test_indirect_call_followed_by_cbnz_x0_is_reported(self):
        report = summarize_immediate_call_result_zero_tests(
            words(blr(8), cbnz_x0(5), 0xD65F03C0)
        )
        self.assertEqual(report["recognized_call_count"], 1)
        item = report["observations"][0]
        self.assertEqual(item["call_kind"], "indirect_blr")
        self.assertEqual(item["tested_register"], "x0")
        self.assertEqual(item["branch_when"], "nonzero")
        self.assertFalse(item["branch_target_within_window"])
        self.assertIsNone(item["branch_target_instruction_index"])

    def test_direct_call_followed_by_tbz_w0_reports_tested_bit(self):
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), tbz_w0(7, 2), 0xD503201F, 0xD65F03C0)
        )
        self.assertEqual(report["immediate_w0_x0_bit_test_count"], 1)
        self.assertEqual(report["calls_without_any_recognized_result_test"], 0)
        self.assertEqual(report["bit_test_observations"][0], {
            "call_instruction_index": 0,
            "branch_instruction_index": 1,
            "call_kind": "direct_bl",
            "tested_register": "w0",
            "tested_bit": 7,
            "branch_when": "zero",
            "branch_target_delta_instructions": 2,
            "branch_target_within_window": True,
            "branch_target_instruction_index": 3,
        })

    def test_indirect_call_followed_by_tbnz_x0_reports_bit_63_and_negative_target(self):
        report = summarize_immediate_call_result_zero_tests(
            words(blr(8), tbnz_x0(63, -2), 0xD65F03C0)
        )
        self.assertEqual(report["immediate_w0_x0_bit_test_count"], 1)
        item = report["bit_test_observations"][0]
        self.assertEqual(item["call_kind"], "indirect_blr")
        self.assertEqual(item["tested_register"], "x0")
        self.assertEqual(item["tested_bit"], 63)
        self.assertEqual(item["branch_when"], "nonzero")
        self.assertEqual(item["branch_target_delta_instructions"], -2)
        self.assertFalse(item["branch_target_within_window"])
        self.assertIsNone(item["branch_target_instruction_index"])

    def test_bit_test_rejects_other_registers_and_non_matching_opcodes(self):
        tbz_w1 = 0x36000001
        for word in (tbz_w1, 0x34000000, 0xD503201F):
            with self.subTest(word=word):
                self.assertIsNone(_decode_tbz_tbnz_on_x0(word))
        self.assertIsNone(_decode_tbz_tbnz_on_x0(True))
        self.assertEqual(_decode_tbz_tbnz_on_x0(tbz_w0(31, 1))["tested_bit"], 31)
        self.assertEqual(_decode_tbz_tbnz_on_x0(tbnz_x0(63, 1))["tested_bit"], 63)

    def test_direct_call_cmp_w0_zero_b_eq_is_reported(self):
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), 0x7100001F, b_cond(0, 2), 0xD503201F, 0xD65F03C0)
        )
        self.assertEqual(report["immediate_w0_x0_zero_test_count"], 0)
        self.assertEqual(report["immediate_cmp_zero_bcond_count"], 1)
        self.assertEqual(report["calls_without_either_zero_test_shape"], 0)
        self.assertEqual(report["cmp_zero_bcond_observations"][0], {
            "call_instruction_index": 0,
            "compare_instruction_index": 1,
            "branch_instruction_index": 2,
            "call_kind": "direct_bl",
            "tested_register": "w0",
            "branch_when": "zero",
            "branch_target_delta_instructions": 2,
            "branch_target_within_window": True,
            "branch_target_instruction_index": 4,
        })

    def test_indirect_call_cmp_x0_zero_b_ne_supports_negative_target_delta(self):
        report = summarize_immediate_call_result_zero_tests(
            words(blr(8), 0xF100001F, b_cond(1, -3), 0xD65F03C0)
        )
        self.assertEqual(report["immediate_cmp_zero_bcond_count"], 1)
        item = report["cmp_zero_bcond_observations"][0]
        self.assertEqual(item["call_kind"], "indirect_blr")
        self.assertEqual(item["tested_register"], "x0")
        self.assertEqual(item["branch_when"], "nonzero")
        self.assertEqual(item["branch_target_delta_instructions"], -3)
        self.assertFalse(item["branch_target_within_window"])
        self.assertIsNone(item["branch_target_instruction_index"])

    def test_cmp_branch_rejects_other_registers_immediates_and_conditions(self):
        cmp_w1_zero = 0x7100003F
        cmp_w0_one = 0x7100041F
        for compare, branch in (
            (cmp_w1_zero, b_cond(0, 1)),
            (cmp_w0_one, b_cond(0, 1)),
            (0x7100001F, b_cond(8, 1)),
        ):
            with self.subTest(compare=compare, branch=branch):
                report = summarize_immediate_call_result_zero_tests(
                    words(bl(), compare, branch, 0xD65F03C0)
                )
                self.assertEqual(report["immediate_cmp_zero_bcond_count"], 0)
                self.assertEqual(report["calls_without_either_zero_test_shape"], 1)

    def test_cmp_branch_does_not_bridge_an_intervening_instruction(self):
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), 0x7100001F, 0xD503201F, b_cond(0, 1))
        )
        self.assertEqual(report["immediate_cmp_zero_bcond_count"], 0)
        self.assertEqual(report["calls_without_either_zero_test_shape"], 1)

    def test_nonzero_register_and_non_adjacent_cbz_tests_are_not_attributed(self):
        cbz_w1 = 0x34000001
        mov_w0_w1 = 0x2A0103E0
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), cbz_w1, bl(), mov_w0_w1, cbz_w0(1))
        )
        self.assertEqual(report["recognized_call_count"], 2)
        self.assertEqual(report["immediate_w0_x0_zero_test_count"], 0)
        self.assertEqual(report["calls_without_immediate_w0_x0_zero_test"], 2)
        self.assertEqual(report["calls_without_either_zero_test_shape"], 2)

    def test_each_observation_kind_has_an_independent_report_cap(self):
        report = summarize_immediate_call_result_zero_tests(
            words(
                bl(), cbz_w0(1),
                blr(), cbnz_x0(1),
                bl(), tbz_w0(0, 1),
                blr(), tbnz_x0(63, 1),
                bl(), 0x7100001F, b_cond(0, 1),
                blr(), 0xF100001F, b_cond(1, 1),
            ),
            max_observations=1,
        )
        self.assertEqual(report["immediate_w0_x0_zero_test_count"], 2)
        self.assertEqual(report["immediate_w0_x0_bit_test_count"], 2)
        self.assertEqual(report["immediate_cmp_zero_bcond_count"], 2)
        self.assertEqual(len(report["observations"]), 1)
        self.assertEqual(len(report["bit_test_observations"]), 1)
        self.assertEqual(len(report["cmp_zero_bcond_observations"]), 1)
        self.assertTrue(report["observations_truncated"])
        self.assertTrue(report["bit_test_observations_truncated"])
        self.assertTrue(report["cmp_zero_bcond_observations_truncated"])

    def test_decoder_rejects_other_registers_and_non_matching_instructions(self):
        self.assertIsNone(_decode_cbz_cbnz_on_x0(0x34000001))
        self.assertIsNone(_decode_cbz_cbnz_on_x0(0x54000000))
        self.assertEqual(_decode_cbz_cbnz_on_x0(cbz_w0(-1))["branch_when"], "zero")
        self.assertEqual(_decode_cmp_zero_on_x0(0x7100001F), "w0")
        self.assertEqual(_decode_cmp_zero_on_x0(0xF100001F), "x0")
        self.assertIsNone(_decode_cmp_zero_on_x0(0x7100003F))
        self.assertEqual(_decode_b_cond_eq_ne(b_cond(0, -1))["branch_when"], "zero")
        self.assertEqual(_decode_b_cond_eq_ne(b_cond(1, 1))["branch_when"], "nonzero")
        self.assertIsNone(_decode_b_cond_eq_ne(b_cond(8, 1)))
        self.assertIsNone(_decode_b_cond_eq_ne(0xD503201F))

    def test_invalid_input_and_limits_fail_closed(self):
        invalid_calls = (
            lambda: summarize_immediate_call_result_zero_tests(bytearray()),
            lambda: summarize_immediate_call_result_zero_tests(b"abc"),
            lambda: summarize_immediate_call_result_zero_tests(b"\\x00" * (64 * 1024 + 4)),
            lambda: summarize_immediate_call_result_zero_tests(b"", max_observations=0),
            lambda: summarize_immediate_call_result_zero_tests(b"", max_observations=True),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main()
