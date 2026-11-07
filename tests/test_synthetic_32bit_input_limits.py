"""Resource limits for the 32-bit synthetic transport, not an AOW wire claim."""
import unittest

from server.synthetic_framing import FrameError, LengthPrefixedFrames


class Synthetic32BitInputLimitTests(unittest.TestCase):
    def test_rejects_bad_chunk_limits(self):
        for value in (0, -1, True, 1.5, "5"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    LengthPrefixedFrames(max_chunk_bytes=value)

    def test_oversize_chunk_discards_partial_header(self):
        codec = LengthPrefixedFrames(max_payload=8, max_chunk_bytes=4)
        self.assertEqual(codec.feed(b"\x00\x00"), [])
        with self.assertRaises(FrameError):
            codec.feed(b"x" * 5)
        wire = codec.encode(b"ok")
        self.assertEqual(codec.feed(wire[:4]), [])
        self.assertEqual(codec.feed(wire[4:]), [b"ok"])

    def test_oversize_chunk_discards_partial_body(self):
        codec = LengthPrefixedFrames(max_payload=8, max_chunk_bytes=4)
        wire = codec.encode(b"hello")
        self.assertEqual(codec.feed(wire[:4]), [])
        self.assertEqual(codec.feed(wire[4:6]), [])
        with self.assertRaises(FrameError):
            codec.feed(b"z" * 5)
        fresh = codec.encode(b"yes")
        self.assertEqual(codec.feed(fresh[:4]), [])
        self.assertEqual(codec.feed(fresh[4:]), [b"yes"])

    def test_fragmented_valid_frames_under_limit(self):
        codec = LengthPrefixedFrames(max_payload=8, max_chunk_bytes=3)
        payloads = [b"", b"hello", b"xy"]
        wire = b"".join(codec.encode(p) for p in payloads)
        result = []
        for i in range(0, len(wire), 3):
            result.extend(codec.feed(wire[i:i + 3]))
        self.assertEqual(result, payloads)


if __name__ == "__main__":
    unittest.main()
