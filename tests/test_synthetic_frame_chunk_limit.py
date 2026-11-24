"""Regression tests for synthetic framing input chunk limits (not APK wire tests)."""
import unittest

from server.synthetic_frame_codec import (
    FrameError, SyntheticFrameDecoder, encode_synthetic_frame,
)


class SyntheticChunkLimitTests(unittest.TestCase):
    def test_rejects_oversized_chunk_before_buffering(self):
        decoder = SyntheticFrameDecoder(max_payload=8, max_chunk_bytes=4)
        with self.assertRaises(FrameError):
            decoder.feed(b"x" * 5)
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_oversized_chunk_clears_existing_partial_frame(self):
        decoder = SyntheticFrameDecoder(max_payload=8, max_chunk_bytes=4)
        decoder.feed(encode_synthetic_frame(b"abc")[:3])
        self.assertEqual(decoder.buffered_bytes, 3)
        with self.assertRaises(FrameError):
            decoder.feed(b"z" * 5)
        self.assertEqual(decoder.buffered_bytes, 0)
        self.assertEqual(decoder.feed(encode_synthetic_frame(b"a")), [b"a"])

    def test_chunk_equal_to_limit_is_accepted(self):
        decoder = SyntheticFrameDecoder(max_payload=8, max_chunk_bytes=4)
        frame = encode_synthetic_frame(b"ab")
        self.assertEqual(decoder.feed(frame), [b"ab"])

    def test_fragmented_frame_with_small_chunk_limit(self):
        decoder = SyntheticFrameDecoder(max_payload=8, max_chunk_bytes=3)
        frame = encode_synthetic_frame(b"abcde")
        self.assertEqual(decoder.feed(frame[:3]), [])
        self.assertEqual(decoder.feed(frame[3:6]), [])
        self.assertEqual(decoder.feed(frame[6:]), [b"abcde"])

    def test_invalid_chunk_limits(self):
        for limit in (0, -1, True, 1.5, "3", None):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    SyntheticFrameDecoder(max_chunk_bytes=limit)


if __name__ == "__main__":
    unittest.main()
