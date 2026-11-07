"""Exhaustive small synthetic framing boundaries; no real AOW wire claims."""
import unittest

from server.synthetic_frame_codec import (
    FrameError,
    SyntheticFrameDecoder,
    encode_synthetic_frame,
)


class SyntheticFramingBoundaryTests(unittest.TestCase):
    def test_every_two_chunk_split_for_mixed_frames(self):
        payloads = [b"a", b"\x00\xff", b"last"]
        stream = b"".join(encode_synthetic_frame(p) for p in payloads)
        for cut in range(len(stream) + 1):
            with self.subTest(cut=cut):
                decoder = SyntheticFrameDecoder()
                actual = decoder.feed(stream[:cut])
                actual += decoder.feed(stream[cut:])
                self.assertEqual(actual, payloads)
                self.assertEqual(decoder.buffered_bytes, 0)

    def test_one_byte_chunks_and_empty_feeds(self):
        payloads = [b"x", b"yz", b"\x00"]
        stream = b"".join(encode_synthetic_frame(p) for p in payloads)
        decoder = SyntheticFrameDecoder(max_chunk_bytes=1)
        actual = []
        for byte in stream:
            actual.extend(decoder.feed(bytes([byte])))
            actual.extend(decoder.feed(b""))
        self.assertEqual(actual, payloads)
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_invalid_header_across_feeds_clears_partial_state(self):
        decoder = SyntheticFrameDecoder(max_payload=3)
        self.assertEqual(decoder.feed(b"\x00"), [])
        with self.assertRaises(FrameError):
            decoder.feed(b"\x04")
        self.assertEqual(decoder.buffered_bytes, 0)
        self.assertEqual(decoder.feed(encode_synthetic_frame(b"ok")), [b"ok"])

    def test_oversize_chunk_clears_partial_state(self):
        decoder = SyntheticFrameDecoder(max_chunk_bytes=4)
        self.assertEqual(decoder.feed(b"\x00\x03a"), [])
        with self.assertRaises(FrameError):
            decoder.feed(b"x" * 5)
        self.assertEqual(decoder.buffered_bytes, 0)
        self.assertEqual(decoder.feed(encode_synthetic_frame(b"b")), [b"b"])

    def test_partial_frame_buffer_bound(self):
        decoder = SyntheticFrameDecoder(max_payload=8, max_chunk_bytes=4)
        frame = encode_synthetic_frame(b"x" * 8)
        for start in range(0, len(frame), 4):
            decoder.feed(frame[start:start + 4])
            self.assertLessEqual(decoder.buffered_bytes, 9)
        self.assertEqual(decoder.buffered_bytes, 0)


if __name__ == "__main__":
    unittest.main()
