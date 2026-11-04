"""Synthetic-only frame probe tests; no AOW packet assumptions."""
import unittest

from server.offline_frame_probe import FrameSpec, LengthFrameDecoder, FrameDecodeError


class OfflineFrameProbeTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "big"))
        self.assertEqual(decoder.feed(b"\x00"), [])
        self.assertEqual(decoder.feed(b"\x03a"), [])
        self.assertEqual(decoder.feed(b"bc"), [b"abc"])
        decoder.finish()

    def test_coalesced_frames_and_partial_tail(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "little"))
        self.assertEqual(decoder.feed(b"\x01A\x02B"), [b"A"])
        self.assertEqual(decoder.feed(b"C"), [b"BC"])
        decoder.finish()

    def test_little_endian_header_included(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "little", includes_header=True))
        self.assertEqual(decoder.feed(b"\x05\x00abc"), [b"abc"])

    def test_zero_length_frame(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        self.assertEqual(decoder.feed(b"\x00\x01x"), [b"", b"x"])

    def test_reject_oversize_and_poison_decoder(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "big", max_payload=3))
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x00\x04")
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x00\x01a")

    def test_reject_header_smaller_than_declared_inclusive(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "big", includes_header=True))
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x00\x01")

    def test_truncation(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        decoder.feed(b"\x02a")
        with self.assertRaises(FrameDecodeError):
            decoder.finish()

    def test_reject_unbounded_or_ambiguous_config(self):
        for args in ((3, "big"), (2, "middle")):
            with self.assertRaises(ValueError):
                FrameSpec(*args)
        with self.assertRaises(ValueError):
            FrameSpec(2, "big", max_payload=0)
        with self.assertRaises(TypeError):
            LengthFrameDecoder(None)
        with self.assertRaises(TypeError):
            LengthFrameDecoder(FrameSpec(1, "big")).feed(bytearray(b"\x01a"))


if __name__ == "__main__":
    unittest.main()
