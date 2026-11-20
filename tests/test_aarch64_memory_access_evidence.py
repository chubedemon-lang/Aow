"""Synthetic AArch64 memory-access decoder tests; no APK fixture."""
import json
import struct
import unittest

from tools.aarch64_memory_access_evidence import (
    decode_unsigned_immediate_memory_access,
    decode_unscaled_immediate_memory_access,
    decode_integer_immediate_memory_access,
    decode_integer_memory_access,
    decode_register_offset_memory_access,
    decode_integer_pair_memory_access,
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




def encode_register_offset(*, size, opc, base, target, index, option=3, scaled=False):
    """Encode one integer register-offset LDR/STR instruction."""
    return (
        (size << 30)
        | 0x38200800
        | (opc << 22)
        | (index << 16)
        | (option << 13)
        | (int(scaled) << 12)
        | (base << 5)
        | target
    )


def encode_pair_access(*, element_bytes, load, base, target, target2, immediate, mode=2):
    """Encode a 32-bit or 64-bit integer LDP/STP addressing form."""
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

    def test_decodes_register_offset_loads_and_stores(self):
        cases = (
            (0xF8626820, "load", 8, "x0", "x2", "lsl", 0),
            (0xF8657883, "load", 8, "x3", "x5", "lsl", 3),
            (0xB86858E6, "load", 4, "w6", "w8", "uxtw", 2),
            (0x386BC949, "load", 1, "w9", "w11", "sxtw", 0),
            (0xF82E79AC, "store", 8, "x12", "x14", "lsl", 3),
            (0xF871FA0F, "load", 8, "x15", "x17", "sxtx", 3),
        )
        for word, operation, width, target, index, extend, shift in cases:
            with self.subTest(word=hex(word)):
                result = decode_register_offset_memory_access(word)
                self.assertEqual(result["operation"], operation)
                self.assertEqual(result["access_bytes"], width)
                self.assertEqual(result["target_register"], target)
                self.assertEqual(result["index_register"], index)
                self.assertEqual(result["index_extend"], extend)
                self.assertEqual(result["scale_shift"], shift)
                self.assertIsNone(result["byte_offset"])
                self.assertEqual(result["addressing_mode"], "register_offset")
                self.assertEqual(result["base_update_bytes"], 0)
                self.assertEqual(decode_integer_memory_access(word), result)
                self.assertIsNone(decode_integer_immediate_memory_access(word))

    def test_register_offset_decoder_rejects_reserved_and_non_integer_forms(self):
        rejected = (
            encode_register_offset(
                size=3, opc=1, base=1, target=0, index=2, option=0
            ),
            encode_register_offset(
                size=3, opc=1, base=1, target=0, index=2, option=1
            ),
            encode_register_offset(
                size=3, opc=1, base=1, target=0, index=2, option=4
            ),
            encode_register_offset(
                size=3, opc=1, base=1, target=0, index=2, option=5
            ),
            encode_register_offset(
                size=3, opc=2, base=1, target=0, index=2
            ),
            encode_register_offset(
                size=3, opc=3, base=1, target=0, index=2
            ),
            encode_register_offset(
                size=3, opc=1, base=1, target=0, index=2
            ) | (1 << 26),
            True,
            -1,
            1 << 32,
        )
        for word in rejected:
            with self.subTest(word=word):
                self.assertIsNone(decode_register_offset_memory_access(word))

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

    def test_decodes_integer_pair_load_store_and_writeback_modes(self):
        cases = (
            (0xA9BF7BFD, "store", 16, 8, "x29", "x30", -16, "pre_index", -16),
            (0xA8C17BFD, "load", 16, 8, "x29", "x30", 0, "post_index", 16),
            (0xA90153F3, "store", 16, 8, "x19", "x20", 16, "signed_offset", 0),
            (
                encode_pair_access(
                    element_bytes=4, load=True, base=1, target=2,
                    target2=3, immediate=-1, mode=2,
                ),
                "load", 8, 4, "w2", "w3", -8, "signed_offset", 0,
            ),
        )
        for word, operation, total_bytes, element_bytes, target, target2, offset, mode, update in cases:
            with self.subTest(word=hex(word)):
                result = decode_integer_pair_memory_access(word)
                self.assertEqual(result, {
                    "operation": operation,
                    "access_bytes": total_bytes,
                    "element_bytes": element_bytes,
                    "access_count": 2,
                    "base_register": "sp" if ((word >> 5) & 31) == 31 else f"x{(word >> 5) & 31}",
                    "target_register": target,
                    "target_register2": target2,
                    "byte_offset": offset,
                    "addressing_mode": mode,
                    "base_update_bytes": update,
                })
                self.assertEqual(decode_integer_memory_access(word), result)
                self.assertIsNone(decode_integer_immediate_memory_access(word))

    def test_pair_decoder_rejects_non_temporal_simd_ldpsw_reserved_and_alias_forms(self):
        rejected = (
            encode_pair_access(
                element_bytes=8, load=True, base=1, target=2,
                target2=3, immediate=0, mode=0,
            ),
            encode_pair_access(
                element_bytes=8, load=True, base=1, target=2,
                target2=3, immediate=0,
            ) | (1 << 26),
            0x69400000,  # LDPSW signed-extending pair form
            0xE9400000,  # reserved pair opc
            encode_pair_access(
                element_bytes=8, load=True, base=2, target=2,
                target2=3, immediate=1, mode=3,
            ),
            encode_pair_access(
                element_bytes=8, load=True, base=3, target=2,
                target2=3, immediate=1, mode=1,
            ),
            encode_pair_access(
                element_bytes=8, load=True, base=1, target=2,
                target2=2, immediate=0, mode=2,
            ),
            True,
            -1,
            1 << 32,
        )
        for word in rejected:
            with self.subTest(word=word):
                self.assertIsNone(decode_integer_pair_memory_access(word))

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
