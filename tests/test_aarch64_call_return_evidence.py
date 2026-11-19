"""Synthetic tests for immediate AArch64 call-result zero-test evidence."""
import struct
import unittest

from tools.aarch64_call_return_evidence import (
    _decode_cbz_cbnz_on_x0,
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

    def test_nonzero_register_and_non_adjacent_tests_are_not_attributed(self):
        cbz_w1 = 0x34000001
        mov_w0_w1 = 0x2A0103E0
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), cbz_w1, bl(), mov_w0_w1, cbz_w0(1))
        )
        self.assertEqual(report["recognized_call_count"], 2)
        self.assertEqual(report["immediate_w0_x0_zero_test_count"], 0)
        self.assertEqual(report["calls_without_immediate_w0_x0_zero_test"], 2)

    def test_observation_cap_preserves_total_match_count(self):
        report = summarize_immediate_call_result_zero_tests(
            words(bl(), cbz_w0(1), blr(), cbnz_x0(1)),
            max_observations=1,
        )
        self.assertEqual(report["immediate_w0_x0_zero_test_count"], 2)
        self.assertEqual(len(report["observations"]), 1)
        self.assertTrue(report["observations_truncated"])

    def test_decoder_rejects_other_registers_and_non_cbz_instructions(self):
        self.assertIsNone(_decode_cbz_cbnz_on_x0(0x34000001))
        self.assertIsNone(_decode_cbz_cbnz_on_x0(0x54000000))
        self.assertEqual(_decode_cbz_cbnz_on_x0(cbz_w0(-1))["branch_when"], "zero")

    def test_invalid_input_and_limits_fail_closed(self):
        invalid_calls = (
            lambda: summarize_immediate_call_result_zero_tests(bytearray()),
            lambda: summarize_immediate_call_result_zero_tests(b"abc"),
            lambda: summarize_immediate_call_result_zero_tests(b"\x00" * (64 * 1024 + 4)),
            lambda: summarize_immediate_call_result_zero_tests(b"", max_observations=0),
            lambda: summarize_immediate_call_result_zero_tests(b"", max_observations=True),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main()
