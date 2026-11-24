"""Synthetic-only stream framing regression tests."""
import unittest

from server.synthetic_length_prefix_framing import (
    FrameError, LengthPrefixDecoder, encode_frame,
)


class SyntheticFramingTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        decoder = LengthPrefixDecoder()
        wire = encode_frame(b"abc")
        self.assertEqual(decoder.feed(wire[:2]), ())
        self.assertEqual(decoder.feed(wire[2:5]), ())
        self.assertEqual(decoder.feed(wire[5:]), (b"abc",))

    def test_multiple_frames_in_one_chunk(self):
        decoder = LengthPrefixDecoder(max_payload=8)
        self.assertEqual(decoder.feed(encode_frame(b"a") + encode_frame(b"bc")), (b"a", b"bc"))

    def test_many_valid_frames_can_exceed_single_frame_buffer_limit(self):
        decoder = LengthPrefixDecoder(max_payload=2)
        wire = encode_frame(b"ab") * 100
        self.assertEqual(decoder.feed(wire), (b"ab",) * 100)

    def test_rejects_zero_and_oversized_frame(self):
        for header in (bytes.fromhex("00000000"), bytes.fromhex("00000009")):
            with self.subTest(header=header):
                with self.assertRaises(FrameError):
                    LengthPrefixDecoder(max_payload=8).feed(header)

    def test_invalid_header_clears_pending(self):
        decoder = LengthPrefixDecoder(max_payload=8)
        self.assertEqual(decoder.feed(bytes.fromhex("0000")), ())
        with self.assertRaises(FrameError):
            decoder.feed(bytes.fromhex("0009"))
        self.assertEqual(decoder.feed(encode_frame(b"ok")), (b"ok",))

    def test_partial_large_frame_stays_bounded(self):
        decoder = LengthPrefixDecoder(max_payload=8)
        self.assertEqual(decoder.feed(bytes.fromhex("00000008") + b"123"), ())
        self.assertEqual(decoder.feed(b"45678"), (b"12345678",))

    def test_encoder_rejects_invalid_input(self):
        for value in (b"", bytearray(b"a"), b"123456789"):
            with self.subTest(value=value):
                with self.assertRaises(FrameError):
                    encode_frame(value, max_payload=8)

    def test_rejects_invalid_configuration(self):
        for value in (0, -1, True, 2 ** 40):
            with self.subTest(value=value):
                with self.assertRaises(FrameError):
                    LengthPrefixDecoder(max_payload=value)


if __name__ == "__main__":
    unittest.main()
