"""Synthetic AArch64 memory-access decoder tests; no APK fixture."""
import json
import struct
import unittest

from tools.aarch64_memory_access_evidence import (
    decode_unsigned_immediate_memory_access,
    summarize_unsigned_immediate_memory_accesses,
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


def code_bytes(*words):
    return b"".join(struct.pack("<I", word) for word in words)


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


if __name__ == "__main__":
    unittest.main()
