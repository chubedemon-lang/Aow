"""Exhaustive small synthetic framing split matrix; NOT APK protocol evidence."""
import unittest

from server.synthetic_stream_framing import (
    FixtureFrameDecoder, FixtureFrameError, encode_fixture_frame,
)


class FramingBoundaryMatrixTests(unittest.TestCase):
    def test_every_two_way_split(self):
        payloads = (b"a", b"hello", bytes(range(16)))
        wire = b"".join(encode_fixture_frame(p, 16) for p in payloads)
        for cut in range(len(wire) + 1):
            with self.subTest(cut=cut):
                decoder = FixtureFrameDecoder(16)
                frames = decoder.feed(wire[:cut])
                frames += decoder.feed(b"")
                frames += decoder.feed(wire[cut:])
                self.assertEqual(frames, list(payloads))
                self.assertEqual(decoder.buffered_bytes, 0)

    def test_bytewise_delivery_and_empty_chunks(self):
        payloads = [b"abc", b"defg", b"x"]
        wire = b"".join(encode_fixture_frame(p, 4) for p in payloads)
        decoder = FixtureFrameDecoder(4)
        received = []
        for byte in wire:
            received.extend(decoder.feed(bytes((byte,))))
            self.assertEqual(decoder.feed(b""), [])
            self.assertLessEqual(decoder.buffered_bytes, 8)
        self.assertEqual(received, payloads)
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_invalid_header_split_at_every_boundary(self):
        for invalid_size in (0, 5, 0xFFFFFFFF):
            wire = invalid_size.to_bytes(4, "big")
            for cut in range(5):
                with self.subTest(invalid_size=invalid_size, cut=cut):
                    decoder = FixtureFrameDecoder(4)
                    if cut < 4:
                        self.assertEqual(decoder.feed(wire[:cut]), [])
                    with self.assertRaises(FixtureFrameError):
                        decoder.feed(wire[cut:])
                    self.assertEqual(decoder.buffered_bytes, 0)
                    with self.assertRaises(FixtureFrameError):
                        decoder.feed(b"")


if __name__ == "__main__":
    unittest.main()
