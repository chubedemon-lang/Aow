"""Synthetic framing regression tests; not evidence of AOW wire format."""
import unittest

from server.synthetic_stream_framing import (
    FixtureFrameDecoder, FixtureFrameError, encode_fixture_frame,
)


class FixtureFramingTests(unittest.TestCase):
    def test_fragmented_header_and_payload(self):
        wire = encode_fixture_frame(b"hello")
        decoder = FixtureFrameDecoder()
        self.assertEqual(decoder.feed(wire[:2]), [])
        self.assertEqual(decoder.feed(wire[2:6]), [])
        self.assertEqual(decoder.feed(wire[6:]), [b"hello"])
        self.assertEqual(decoder.buffered_bytes, 0)

    def test_multiple_frames_and_partial_tail(self):
        decoder = FixtureFrameDecoder()
        wire = encode_fixture_frame(b"a") + encode_fixture_frame(b"bc")
        self.assertEqual(decoder.feed(wire[:-1]), [b"a"])
        self.assertEqual(decoder.feed(wire[-1:]), [b"bc"])

    def test_reject_oversized_header_and_fail_closed(self):
        decoder = FixtureFrameDecoder(max_payload=8)
        with self.assertRaises(FixtureFrameError):
            decoder.feed((9).to_bytes(4, "big"))
        self.assertEqual(decoder.buffered_bytes, 0)
        with self.assertRaises(FixtureFrameError):
            decoder.feed(encode_fixture_frame(b"a"))

    def test_reject_zero_length_and_invalid_types(self):
        decoder = FixtureFrameDecoder()
        with self.assertRaises(FixtureFrameError):
            decoder.feed("not bytes")
        with self.assertRaises(FixtureFrameError):
            decoder.feed(b"\x00\x00\x00\x00")
        for payload in (b"", bytearray(b"x"), "x"):
            with self.subTest(payload=payload), self.assertRaises(FixtureFrameError):
                encode_fixture_frame(payload)

    def test_capacity_boundary_and_invalid_limits(self):
        wire = encode_fixture_frame(b"1234", max_payload=4)
        self.assertEqual(FixtureFrameDecoder(4).feed(wire), [b"1234"])
        with self.assertRaises(FixtureFrameError):
            encode_fixture_frame(b"12345", max_payload=4)
        for limit in (0, -1, True, 1048577):
            with self.subTest(limit=limit), self.assertRaises(FixtureFrameError):
                FixtureFrameDecoder(limit)


if __name__ == "__main__":
    unittest.main()
