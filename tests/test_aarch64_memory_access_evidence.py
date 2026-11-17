"""Synthetic AArch64 memory-access decoder tests; no APK fixture."""
import json
import struct
import unittest

from tools.aarch64_memory_access_evidence import (
    decode_unsigned_immediate_memory_access,
    decode_unscaled_immediate_memory_access,
    decode_integer_immediate_memory_access,
    summarize_unsigned_immediate_memory_accesses,
    summarize_control_flow_memory_accesses,
)


def encode_access(*, size, opc, base, target, immediate):
    """Encode one integer unsigned-offset LDR/STR instruction."""
    return (
        (size << 30)
        | 0x39000000
        | (opc << 22)
        | (immediate << 10)
        | (base << 5)
        | target
    )



def encode_unscaled_access(*, size, opc, base, target, immediate, mode=0):
    """Encode an integer unscaled or pre/post-indexed memory operation."""
    return (
        (size << 30)
        | 0x38000000
        | (opc << 22)
        | ((immediate & 0x1FF) << 12)
        | (mode << 10)
        | (base << 5)
        | target
    )


def code_bytes(*words):
    return b"".join(struct.pack("<I", word) for word in words)


def encode_b(offset_bytes):
    return 0x14000000 | ((offset_bytes // 4) & 0x03FFFFFF)


def encode_b_cond(offset_bytes):
    return 0x54000000 | (((offset_bytes // 4) & 0x7FFFF) << 5)


class AArch64MemoryAccessEvidenceTests(unittest.TestCase):
    def test_decodes_scaled_byte_half_word_and_doubleword_offsets(self):
        cases = (
            (0, 0, 8, 9, 7, "store", 1, "w9", 7),
            (1, 1, 11, 10, 3, "load", 2, "w10", 6),
            (2, 0, 8, 9, 3, "store", 4, "w9", 12),
            (3, 1, 31, 31, 3, "load", 8, "xzr", 24),
        )
        for size, opc, base, target, immediate, operation, width, target_name, offset in cases:
            with self.subTest(size=size, opc=opc):
                result = decode_unsigned_immediate_memory_access(
                    encode_access(
                        size=size, opc=opc, base=base, target=target,
                        immediate=immediate,
                    )
                )
                self.assertEqual(
                    result,
                    {
                        "operation": operation,
                        "access_bytes": width,
                        "base_register": "sp" if base == 31 else f"x{base}",
                        "target_register": target_name,
                        "byte_offset": offset,
                    },
                )

    def test_rejects_simd_sign_extending_unscaled_and_unrelated_instructions(self):
        word_load = encode_access(
            size=2, opc=1, base=8, target=9, immediate=2
        )
        rejected = (
            word_load | (1 << 26),  # SIMD/FP V bit
            encode_access(size=2, opc=2, base=8, target=9, immediate=2),
            0xB8400C20,  # LDUR W0, [X1, #0]
            0xD503201F,  # NOP
            -1,
            1 << 32,
            True,
        )
        for word in rejected:
            with self.subTest(word=word):
                self.assertIsNone(decode_unsigned_immediate_memory_access(word))

    def test_decodes_signed_unscaled_and_pre_post_indexed_forms(self):
        cases = (
            (0xF85F8020, "load", 8, "x0", -8, "unscaled", 0),
            (0xB85FC020, "load", 4, "w0", -4, "unscaled", 0),
            (0x385FF020, "load", 1, "w0", -1, "unscaled", 0),
            (0xF81F8420, "store", 8, "x0", 0, "post_index", -8),
            (0xF81F8C20, "store", 8, "x0", -8, "pre_index", -8),
        )
        for word, operation, width, target, offset, mode, update in cases:
            with self.subTest(word=hex(word)):
                result = decode_unscaled_immediate_memory_access(word)
                self.assertEqual(result, {
                    "operation": operation,
                    "access_bytes": width,
                    "base_register": "x1",
                    "target_register": target,
                    "byte_offset": offset,
                    "addressing_mode": mode,
                    "base_update_bytes": update,
                })

    def test_unscaled_decoder_rejects_unprivileged_and_ambiguous_encodings(self):
        rejected = (
            encode_unscaled_access(
                size=3, opc=1, base=1, target=0, immediate=-8, mode=2
            ),
            encode_unscaled_access(
                size=3, opc=2, base=1, target=0, immediate=-8
            ),
            encode_unscaled_access(
                size=3, opc=1, base=1, target=0, immediate=-8
            ) | (1 << 26),
            encode_unscaled_access(
                size=3, opc=1, base=1, target=1, immediate=8, mode=1
            ),
            True,
            -1,
            1 << 32,
        )
        for word in rejected:
            with self.subTest(word=word):
                self.assertIsNone(decode_unscaled_immediate_memory_access(word))

    def test_combined_decoder_labels_unsigned_and_unscaled_addressing(self):
        unsigned = decode_integer_immediate_memory_access(
            encode_access(size=3, opc=1, base=1, target=0, immediate=2)
        )
        unscaled = decode_integer_immediate_memory_access(0xF85F8020)
        self.assertEqual(unsigned["addressing_mode"], "unsigned_scaled")
        self.assertEqual(unsigned["byte_offset"], 16)
        self.assertEqual(unsigned["base_update_bytes"], 0)
        self.assertEqual(unscaled["addressing_mode"], "unscaled")
        self.assertEqual(unscaled["byte_offset"], -8)

    def test_cfg_summary_includes_unscaled_and_writeback_accesses(self):
        words = (
            encode_access(size=2, opc=1, base=8, target=9, immediate=2),
            0xF85F8020,
            0xF81F8420,
        )
        summary = summarize_control_flow_memory_accesses(
            code_bytes(*words), 0x4000
        )
        self.assertEqual(summary["memory_access_count"], 3)
        self.assertEqual(
            [item["addressing_mode"] for item in summary["memory_accesses"]],
            ["unsigned_scaled", "unscaled", "post_index"],
        )
        self.assertEqual(
            [item["byte_offset"] for item in summary["memory_accesses"]],
            [8, -8, 0],
        )
        self.assertEqual(
            [item["base_update_bytes"] for item in summary["memory_accesses"]],
            [0, 0, -8],
        )

    def test_summary_preserves_instruction_order_and_caps_report(self):
        words = (
            0xD503201F,
            encode_access(size=2, opc=0, base=8, target=9, immediate=3),
            encode_access(size=2, opc=1, base=8, target=10, immediate=4),
            0xD503201F,
            encode_access(size=3, opc=0, base=31, target=31, immediate=1),
        )
        summary = summarize_unsigned_immediate_memory_accesses(
            code_bytes(*words), max_accesses=2
        )
        self.assertEqual(summary["instruction_count"], 5)
        self.assertEqual(summary["memory_access_count"], 3)
        self.assertEqual(
            [item["instruction_index"] for item in summary["memory_accesses"]],
            [1, 2],
        )
        self.assertTrue(summary["memory_accesses_truncated"])
        self.assertFalse(summary["native_addresses_emitted"])
        self.assertFalse(summary["raw_instructions_emitted"])

    def test_empty_window_and_exact_report_limit(self):
        one = code_bytes(encode_access(
            size=0, opc=1, base=1, target=2, immediate=0
        ))
        self.assertEqual(
            summarize_unsigned_immediate_memory_accesses(b"")["memory_access_count"],
            0,
        )
        summary = summarize_unsigned_immediate_memory_accesses(
            one, max_accesses=1
        )
        self.assertEqual(summary["memory_access_count"], 1)
        self.assertFalse(summary["memory_accesses_truncated"])

    def test_rejects_non_exact_bytes_and_invalid_limits(self):
        class BytesSubclass(bytes):
            pass

        with self.assertRaises(ValueError):
            summarize_unsigned_immediate_memory_accesses(BytesSubclass(b"1234"))
        for code in (b"abc", b"x" * (64 * 1024 + 4)):
            with self.subTest(length=len(code)), self.assertRaises(ValueError):
                summarize_unsigned_immediate_memory_accesses(code)
        for limit in (0, True, 513, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                summarize_unsigned_immediate_memory_accesses(b"", max_accesses=limit)

    def test_report_contains_no_native_address_or_instruction_word(self):
        code = code_bytes(encode_access(
            size=2, opc=1, base=8, target=9, immediate=4
        ))
        rendered = json.dumps(
            summarize_unsigned_immediate_memory_accesses(code)
        )
        self.assertNotIn("0x", rendered)
        self.assertNotIn("5000", rendered)
        self.assertNotIn("instruction_word", rendered)


    def test_unconditional_branch_marks_skipped_access_unreachable(self):
        access = encode_access(size=2, opc=1, base=8, target=9, immediate=1)
        summary = summarize_control_flow_memory_accesses(
            code_bytes(encode_b(8), access, access), 0x1000
        )
        self.assertEqual(summary["memory_access_count"], 2)
        self.assertEqual(summary["statically_reachable_memory_access_count"], 1)
        self.assertEqual(summary["statically_unreachable_memory_access_count"], 1)
        self.assertEqual(
            [(item["instruction_index"], item["statically_reachable"])
             for item in summary["memory_accesses"]],
            [(1, False), (2, True)],
        )

    def test_conditional_branch_assumes_both_in_window_outcomes(self):
        access = encode_access(size=2, opc=1, base=8, target=9, immediate=1)
        summary = summarize_control_flow_memory_accesses(
            code_bytes(encode_b_cond(8), access, access), 0x2000
        )
        self.assertEqual(summary["statically_reachable_memory_access_count"], 2)
        self.assertTrue(summary["conditional_edges_assume_both_outcomes"])
        self.assertFalse(summary["path_conditions_evaluated"])
        self.assertTrue(all(
            item["statically_reachable"] for item in summary["memory_accesses"]
        ))

    def test_return_terminates_structural_fallthrough(self):
        access = encode_access(size=2, opc=0, base=8, target=9, immediate=2)
        summary = summarize_control_flow_memory_accesses(
            code_bytes(access, 0xD65F03C0, access), 0x3000
        )
        self.assertEqual(summary["memory_access_count"], 2)
        self.assertEqual(summary["statically_reachable_memory_access_count"], 1)
        self.assertEqual(summary["statically_unreachable_memory_access_count"], 1)

    def test_cfg_report_cap_preserves_counts_and_redacts_addresses(self):
        access = encode_access(size=2, opc=1, base=8, target=9, immediate=1)
        summary = summarize_control_flow_memory_accesses(
            code_bytes(access, access), 0x12345000, max_accesses=1
        )
        self.assertEqual(summary["memory_access_count"], 2)
        self.assertEqual(len(summary["memory_accesses"]), 1)
        self.assertTrue(summary["memory_accesses_truncated"])
        rendered = json.dumps(summary)
        self.assertNotIn("0x12345000", rendered)
        self.assertNotIn("native_address", rendered.replace(
            '"native_addresses_emitted": false', ""
        ))

    def test_cfg_summary_rejects_invalid_window_address_and_limit(self):
        for code, start_va, limit in (
            (b"abc", 0x1000, 128),
            (b"1234", True, 128),
            (b"1234", 0x1001, 128),
            (b"12345678", 0xFFFFFFFFFFFFFFFC, 128),
            (b"", 0x1000, 0),
            (b"", 0x1000, True),
        ):
            with self.subTest(code_length=len(code), start_va=start_va, limit=limit):
                with self.assertRaises(ValueError):
                    summarize_control_flow_memory_accesses(
                        code, start_va, max_accesses=limit
                    )


if __name__ == "__main__":
    unittest.main()
