"""Synthetic regression coverage for direct serializer helper callsite order."""
import struct
import unittest

from tools.il2cpp_native_method_evidence import _summarize_aarch64_calls


def encode_bl(pc, target):
    delta = target - pc
    if delta % 4:
        raise ValueError("AArch64 BL target must be four-byte aligned")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError("AArch64 BL target is outside the immediate range")
    return 0x94000000 | (immediate & 0x03FFFFFF)


class LoginRequestCallsiteSequenceTests(unittest.TestCase):
    def test_repeated_direct_helper_calls_preserve_linear_order(self):
        start = 0x8000
        targets = (0x2000, 0x2020, 0x2000, 0x3000, 0x2020, 0x2000)
        code = b"".join(
            struct.pack("<I", encode_bl(start + index * 4, target))
            for index, target in enumerate(targets)
        )
        helper_targets = {
            0x2000: ["SimpleSerializer::serializeInt"],
            0x2020: ["SimpleSerializer::serializeString"],
        }

        summary = _summarize_aarch64_calls(code, start, helper_targets)

        self.assertEqual(
            summary["direct_helper_call_sequence"],
            [
                "SimpleSerializer::serializeInt",
                "SimpleSerializer::serializeString",
                "SimpleSerializer::serializeInt",
                "SimpleSerializer::serializeString",
                "SimpleSerializer::serializeInt",
            ],
        )
        self.assertEqual(
            summary["direct_helper_call_counts"],
            {
                "SimpleSerializer::serializeInt": 3,
                "SimpleSerializer::serializeString": 2,
            },
        )
        self.assertEqual(summary["direct_calls_not_in_helper_allowlist"], 1)
        self.assertEqual(summary["indirect_call_count"], 0)


if __name__ == "__main__":
    unittest.main()
