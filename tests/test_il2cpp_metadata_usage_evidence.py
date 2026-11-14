"""Synthetic tests for versioned IL2CPP MethodDef usage tokens."""
import unittest

from tools.il2cpp_metadata_usage_evidence import (
    decode_method_def_usage_index,
    encode_method_def_usage_index,
)


class MetadataUsageEvidenceTests(unittest.TestCase):
    def test_v31_method_def_usage_round_trips_with_low_bit_marker(self):
        for index in (0, 1, 321, 0x0FFFFFFF):
            with self.subTest(index=index):
                encoded = encode_method_def_usage_index(index, 31)
                self.assertEqual(
                    decode_method_def_usage_index(encoded, 31),
                    index,
                )

    def test_pre_v27_method_def_usage_uses_unshifted_index(self):
        for index in (0, 1, 321, 0x1FFFFFFF):
            with self.subTest(index=index):
                encoded = encode_method_def_usage_index(index, 26)
                self.assertEqual(
                    decode_method_def_usage_index(encoded, 26),
                    index,
                )

    def test_non_method_def_usage_is_not_promoted(self):
        self.assertIsNone(decode_method_def_usage_index(0x40000003, 31))
        self.assertIsNone(decode_method_def_usage_index(0x80000003, 31))

    def test_v27_plus_token_without_unresolved_marker_is_not_promoted(self):
        self.assertIsNone(decode_method_def_usage_index(0x60000002, 31))

    def test_rejects_invalid_encoded_values_and_versions(self):
        for encoded in (True, -1, 1 << 32):
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                decode_method_def_usage_index(encoded, 31)
        for version in (True, 0, -1):
            with self.subTest(version=version), self.assertRaises(ValueError):
                decode_method_def_usage_index(0x60000003, version)
        for index in (True, -1, 1 << 28):
            with self.subTest(index=index), self.assertRaises(ValueError):
                encode_method_def_usage_index(index, 31)


if __name__ == "__main__":
    unittest.main()
