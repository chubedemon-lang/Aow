"""Recovery and input validation tests for synthetic stream framing only.

No assumptions about the original AOW APK packet format.
"""
import unittest

from server.synthetic_framing import FrameError, LengthPrefixedFrames


class SyntheticFramingRecoveryTests(unittest.TestCase):
    def test_reset_discards_partial_header(self):
        decoder = LengthPrefixedFrames(max_payload=16)
        self.assertEqual(decoder.feed(b"\x00\x00"), [])
        decoder.reset()
        self.assertEqual(decoder.feed(decoder.encode(b"ok")), [b"ok"])

    def test_reset_discards_partial_payload(self):
        decoder = LengthPrefixedFrames(max_payload=16)
        wire = decoder.encode(b"stale")
        self.assertEqual(decoder.feed(wire[:6]), [])
        decoder.reset()
        self.assertEqual(decoder.feed(decoder.encode(b"fresh")), [b"fresh"])

    def test_invalid_chunk_does_not_corrupt_partial_frame(self):
        decoder = LengthPrefixedFrames(max_payload=16)
        wire = decoder.encode(b"hello")
        self.assertEqual(decoder.feed(wire[:5]), [])
        for invalid in (None, "bytes", bytearray(b"x"), memoryview(b"x")):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(TypeError):
                    decoder.feed(invalid)
        self.assertEqual(decoder.feed(wire[5:]), [b"hello"])

    def test_oversized_header_clears_partial_and_allows_recovery(self):
        decoder = LengthPrefixedFrames(max_payload=8)
        self.assertEqual(decoder.feed(b"\x00\x00"), [])
        with self.assertRaises(FrameError):
            decoder.feed(b"\x00\x09")
        self.assertEqual(decoder.feed(decoder.encode(b"recover")), [b"recover"])

    def test_invalid_payload_does_not_mutate_decoder(self):
        decoder = LengthPrefixedFrames(max_payload=8)
        wire = decoder.encode(b"ok")
        self.assertEqual(decoder.feed(wire[:2]), [])
        for invalid in ("x", bytearray(b"x"), None):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(TypeError):
                    decoder.encode(invalid)
        self.assertEqual(decoder.feed(wire[2:]), [b"ok"])


if __name__ == "__main__":
    unittest.main()
