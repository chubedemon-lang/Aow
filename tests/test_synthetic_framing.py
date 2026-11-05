import unittest

from server.synthetic_framing import FrameError, LengthPrefixedFrames


class SyntheticFramingTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        codec = LengthPrefixedFrames()
        wire = codec.encode(b"hello")
        self.assertEqual(codec.feed(wire[:2]), [])
        self.assertEqual(codec.feed(wire[2:6]), [])
        self.assertEqual(codec.feed(wire[6:]), [b"hello"])

    def test_multiple_frames_and_partial_tail(self):
        codec = LengthPrefixedFrames()
        wire = codec.encode(b"a") + codec.encode(b"") + codec.encode(b"xyz")
        self.assertEqual(codec.feed(wire[:-1]), [b"a", b""])
        self.assertEqual(codec.feed(wire[-1:]), [b"xyz"])

    def test_oversize_declared_length_rejected(self):
        codec = LengthPrefixedFrames(max_payload=3)
        with self.assertRaises(FrameError):
            codec.feed(bytes([0, 0, 0, 4]))
        self.assertEqual(codec.feed(codec.encode(b"ok")), [b"ok"])

    def test_oversize_encode_rejected(self):
        with self.assertRaises(FrameError):
            LengthPrefixedFrames(max_payload=2).encode(b"abc")

    def test_type_and_limit_validation(self):
        for limit in (0, -1, True, 0x100000000):
            with self.assertRaises(ValueError):
                LengthPrefixedFrames(limit)
        codec = LengthPrefixedFrames()
        with self.assertRaises(TypeError):
            codec.feed("not bytes")
        with self.assertRaises(TypeError):
            codec.encode(bytearray(b"hi"))

    def test_reset_discards_partial_frame(self):
        codec = LengthPrefixedFrames()
        codec.feed(bytes([0, 0]))
        codec.reset()
        self.assertEqual(codec.feed(codec.encode(b"ok")), [b"ok"])


if __name__ == "__main__":
    unittest.main()
