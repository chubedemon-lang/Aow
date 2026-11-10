import unittest

from server.aow_primitive_codec import AowPrimitiveReader, AowPrimitiveWriter


class AowPrimitiveCodecTests(unittest.TestCase):
    def test_big_endian_integer_vectors(self):
        writer = AowPrimitiveWriter()
        writer.write_int(0x01020304).write_long(0x0102030405060708)
        self.assertEqual(
            writer.to_bytes(),
            bytes.fromhex("010203040102030405060708"),
        )

    def test_signed_integer_round_trip(self):
        values = (-(1 << 31), -1, 0, 1, (1 << 31) - 1)
        writer = AowPrimitiveWriter()
        for value in values:
            writer.write_int(value)
        reader = AowPrimitiveReader(writer.to_bytes())
        self.assertEqual([reader.read_int() for _ in values], list(values))
        self.assertEqual(reader.remaining, 0)
        self.assertEqual(reader.offset, len(writer.to_bytes()))
        reader.require_consumed()

    def test_signed_long_round_trip(self):
        values = (-(1 << 63), -1, 0, 1, (1 << 63) - 1)
        writer = AowPrimitiveWriter()
        for value in values:
            writer.write_long(value)
        reader = AowPrimitiveReader(writer.to_bytes())
        self.assertEqual([reader.read_long() for _ in values], list(values))
        reader.require_consumed()

    def test_char_and_short_are_big_endian_16_bit_values(self):
        writer = AowPrimitiveWriter()
        writer.write_char(0x1234).write_short(-2)
        self.assertEqual(writer.to_bytes(), bytes.fromhex("1234fffe"))
        reader = AowPrimitiveReader(writer.to_bytes())
        self.assertEqual(reader.read_char(), 0x1234)
        self.assertEqual(reader.read_short(), -2)
        reader.require_consumed()

    def test_string_null_empty_and_utf16_code_units(self):
        writer = AowPrimitiveWriter()
        writer.write_string(None).write_string("").write_string("A")
        self.assertEqual(writer.to_bytes(), bytes.fromhex("ffff000000010041"))
        reader = AowPrimitiveReader(writer.to_bytes())
        self.assertIsNone(reader.read_string())
        self.assertEqual(reader.read_string(), "")
        self.assertEqual(reader.read_string(), "A")
        reader.require_consumed()

    def test_non_bmp_string_uses_two_utf16_code_units(self):
        writer = AowPrimitiveWriter().write_string("😀")
        self.assertEqual(writer.to_bytes(), bytes.fromhex("0002d83dde00"))
        self.assertEqual(AowPrimitiveReader(writer.to_bytes()).read_string(), "😀")

    def test_unpaired_surrogate_is_preserved(self):
        value = "\ud800"
        writer = AowPrimitiveWriter().write_string(value)
        self.assertEqual(AowPrimitiveReader(writer.to_bytes()).read_string(), value)

    def test_string_length_boundary(self):
        value = "a" * 0x7FFF
        writer = AowPrimitiveWriter().write_string(value)
        encoded = writer.to_bytes()
        self.assertEqual(encoded[:2], bytes.fromhex("7fff"))
        self.assertEqual(len(encoded), 2 + 0x7FFF * 2)
        self.assertEqual(AowPrimitiveReader(encoded).read_string(), value)

    def test_string_length_above_native_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            AowPrimitiveWriter().write_string("a" * 0x8000)

    def test_reader_treats_negative_string_length_as_null(self):
        reader = AowPrimitiveReader(bytes.fromhex("8000abcd"))
        self.assertIsNone(reader.read_string())
        self.assertEqual(reader.remaining, 2)

    def test_boolean_is_true_only_for_byte_one(self):
        reader = AowPrimitiveReader(bytes.fromhex("000102ff"))
        self.assertFalse(reader.read_boolean())
        self.assertTrue(reader.read_boolean())
        self.assertFalse(reader.read_boolean())
        self.assertFalse(reader.read_boolean())
        writer = AowPrimitiveWriter().write_boolean(False).write_boolean(True)
        self.assertEqual(writer.to_bytes(), bytes.fromhex("0001"))

    def test_truncated_reads_raise_eof(self):
        with self.assertRaises(EOFError):
            AowPrimitiveReader(b"\x01").read_int()
        with self.assertRaises(EOFError):
            AowPrimitiveReader(bytes.fromhex("0002abcd")).read_string()

    def test_writer_validates_primitive_ranges_and_types(self):
        with self.assertRaises(ValueError):
            AowPrimitiveWriter().write_byte(256)
        with self.assertRaises(ValueError):
            AowPrimitiveWriter().write_char(0x10000)
        with self.assertRaises(ValueError):
            AowPrimitiveWriter().write_short(-0x8001)
        with self.assertRaises(ValueError):
            AowPrimitiveWriter().write_int(1 << 31)
        with self.assertRaises(ValueError):
            AowPrimitiveWriter().write_long(1 << 63)
        with self.assertRaises(TypeError):
            AowPrimitiveWriter().write_boolean(1)
        with self.assertRaises(TypeError):
            AowPrimitiveWriter().write_string(1)

    def test_reader_requires_bytes_like_input(self):
        with self.assertRaises(TypeError):
            AowPrimitiveReader("not bytes")

    def test_reader_rejects_trailing_bytes_after_known_payload(self):
        reader = AowPrimitiveReader(bytes.fromhex("01020304ff"))
        self.assertEqual(reader.read_int(), 0x01020304)
        self.assertEqual(reader.offset, 4)
        self.assertEqual(reader.remaining, 1)
        with self.assertRaisesRegex(ValueError, "trailing bytes"):
            reader.require_consumed()

    def test_reader_accepts_exact_payload_boundary(self):
        reader = AowPrimitiveReader(bytes.fromhex("01020304"))
        self.assertEqual(reader.read_int(), 0x01020304)
        self.assertIs(reader.require_consumed(), reader)


if __name__ == "__main__":
    unittest.main()
