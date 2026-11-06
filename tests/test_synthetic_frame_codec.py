"""Synthetic framing tests; no AOW packets or real endpoints."""
import unittest

from server.synthetic_frame_codec import (
    FrameError, SyntheticFrameDecoder, encode_synthetic_frame,
)


class SyntheticFrameTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        frame = encode_synthetic_frame(b"hello")
        decoder = SyntheticFrameDecoder()
        self.assertEqual(decoder.feed(frame[:1]), [])
        self.assertEqual(decoder.feed(frame[1:4]), [])
        self.assertEqual(decoder.feed(frame[4:]), [b"hello"])

    def test_multiple_frames_in_single_chunk(self):
        decoder = SyntheticFrameDecoder()
        stream = encode_synthetic_frame(b"a") + encode_synthetic_frame(b"bc")
        self.assertEqual(decoder.feed(stream), [b"a", b"bc"])
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_complete_frame_and_partial_next(self):
        decoder = SyntheticFrameDecoder()
        stream = encode_synthetic_frame(b"a") + encode_synthetic_frame(b"second")
        self.assertEqual(decoder.feed(stream[:-2]), [b"a"])
        self.assertEqual(decoder.feed(stream[-2:]), [b"second"])

    def test_oversized_header_rejected_without_body(self):
        decoder = SyntheticFrameDecoder(max_payload=4)
        with self.assertRaises(FrameError):
            decoder.feed(bytes([0, 5]))
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_zero_length_rejected(self):
        with self.assertRaises(FrameError):
            SyntheticFrameDecoder().feed(bytes([0, 0]))

    def test_encode_limits(self):
        with self.assertRaises(FrameError):
            encode_synthetic_frame(b"")
        with self.assertRaises(FrameError):
            encode_synthetic_frame(b"abc", max_payload=2)

    def test_bad_types(self):
        with self.assertRaises(TypeError):
            SyntheticFrameDecoder().feed(bytearray(b"ab"))
        with self.assertRaises(TypeError):
            encode_synthetic_frame("not bytes")

    def test_maximum_allowed_payload(self):
        frame = encode_synthetic_frame(b"x" * 8, max_payload=8)
        self.assertEqual(SyntheticFrameDecoder(max_payload=8).feed(frame), [b"x" * 8])

    def test_bad_limit(self):
        for limit in (0, -1, 65536, True, 1.5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    SyntheticFrameDecoder(limit)


if __name__ == "__main__":
    unittest.main()
