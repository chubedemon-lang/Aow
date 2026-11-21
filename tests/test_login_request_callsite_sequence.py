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


    def test_rejects_bytes_subclass_before_length_hook(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom length hook must not run")

        with self.assertRaisesRegex(ValueError, "exact built-in bytes"):
            _summarize_aarch64_calls(HostileBytes(b""), 0x8000, {})

    def test_rejects_mapping_subclass_before_lookup_hooks(self):
        class HostileTargets(dict):
            def items(self):
                raise AssertionError("custom items hook must not run")

            def get(self, *args):
                raise AssertionError("custom get hook must not run")

        with self.assertRaisesRegex(ValueError, "exact built-in dict"):
            _summarize_aarch64_calls(b"", 0x8000, HostileTargets())

    def test_rejects_label_sequence_subclass_before_length_hook(self):
        class HostileLabels(list):
            def __len__(self):
                raise AssertionError("custom length hook must not run")

        with self.assertRaisesRegex(ValueError, "helper target labels"):
            _summarize_aarch64_calls(
                b"", 0x8000, {0x2000: HostileLabels(["serializeInt"])}
            )

    def test_rejects_invalid_helper_target_addresses(self):
        for target in (True, -4, 0x2001):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "aligned built-in integers"):
                    _summarize_aarch64_calls(
                        b"", 0x8000, {target: ["serializeInt"]}
                    )

    def test_rejects_invalid_helper_labels(self):
        for labels in ([""], [None], ("serializeInt", 7)):
            with self.subTest(labels=labels):
                with self.assertRaisesRegex(ValueError, "non-empty strings"):
                    _summarize_aarch64_calls(b"", 0x8000, {0x2000: labels})



if __name__ == "__main__":
    unittest.main()
