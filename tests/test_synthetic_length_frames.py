"""Offline-only framing fixtures; NOT captures from the AOW APK."""
import struct
import unittest

from server.synthetic_length_frames import FrameError, LengthPrefixedFrames


class SyntheticFramingTests(unittest.TestCase):
    def test_fragmented_header_and_payload(self):
        codec = LengthPrefixedFrames(32)
        packet = codec.encode(b"hello")
        self.assertEqual(packet, b"\x00\x00\x00\x05hello")
        self.assertEqual(codec.feed(packet[:2]), ())
        self.assertEqual(codec.feed(packet[2:6]), ())
        self.assertEqual(codec.feed(packet[6:]), (b"hello",))

    def test_coalesced_frames_and_trailing_partial(self):
        codec = LengthPrefixedFrames(32)
        first = codec.encode(b"a")
        second = codec.encode(b"bc")
        self.assertEqual(codec.feed(first + second[:3]), (b"a",))
        self.assertEqual(codec.feed(second[3:]), (b"bc",))

    def test_oversized_header_rejected_and_recoverable(self):
        codec = LengthPrefixedFrames(3)
        with self.assertRaises(FrameError):
            codec.feed(struct.pack(">I", 4))
        self.assertEqual(codec.feed(codec.encode(b"ok")), (b"ok",))

    def test_zero_length_rejected_and_recoverable(self):
        codec = LengthPrefixedFrames()
        with self.assertRaises(FrameError):
            codec.feed(struct.pack(">I", 0))
        self.assertEqual(codec.feed(codec.encode(b"ok")), (b"ok",))

    def test_rejects_invalid_types_and_lengths(self):
        for maximum in (0, True, 16_777_217):
            with self.assertRaises(FrameError):
                LengthPrefixedFrames(maximum)
        codec = LengthPrefixedFrames(2)
        for payload in (b"", b"abc", bytearray(b"a"), "a"):
            with self.assertRaises(FrameError):
                codec.encode(payload)
        with self.assertRaises(FrameError):
            codec.feed(bytearray(b"a"))

    def test_binary_payload_and_reset(self):
        codec = LengthPrefixedFrames()
        payload = bytes(range(256))
        encoded = codec.encode(payload)
        self.assertEqual(codec.feed(encoded), (payload,))
        codec.feed(encoded[:5])
        codec.reset()
        self.assertEqual(codec.feed(encoded), (payload,))

    def test_every_byte_boundary(self):
        codec = LengthPrefixedFrames(64)
        encoded = codec.encode(b"abcdef")
        for byte in encoded[:-1]:
            self.assertEqual(codec.feed(bytes([byte])), ())
        self.assertEqual(codec.feed(encoded[-1:]), (b"abcdef",))

    def test_invalid_header_after_valid_frame_resets_state(self):
        codec = LengthPrefixedFrames(4)
        valid = codec.encode(b"a")
        with self.assertRaises(FrameError):
            codec.feed(valid + struct.pack(">I", 5))
        self.assertEqual(codec.feed(codec.encode(b"b")), (b"b",))


if __name__ == "__main__":
    unittest.main()
