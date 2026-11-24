"""Deterministic stream-boundary regressions for synthetic framing.

These fixtures do not represent the original AOW APK wire protocol.
"""
import random
import unittest

from server.synthetic_framing import FrameError, LengthPrefixedFrames


class SyntheticStreamBoundaryTests(unittest.TestCase):
    def test_randomized_fragmentation_and_coalescing(self):
        rng = random.Random(20261106)
        for _ in range(80):
            payloads = [
                bytes(rng.randrange(256) for _ in range(rng.randrange(0, 96)))
                for _ in range(rng.randrange(1, 15))
            ]
            encoder = LengthPrefixedFrames(max_payload=128)
            wire = b"".join(encoder.encode(payload) for payload in payloads)
            decoder = LengthPrefixedFrames(max_payload=128)
            received = []
            offset = 0
            while offset < len(wire):
                width = rng.randrange(1, 27)
                received.extend(decoder.feed(wire[offset:offset + width]))
                offset += width
            self.assertEqual(received, payloads)
            self.assertEqual(decoder.feed(b""), [])

    def test_interleaved_connections_are_isolated(self):
        first = LengthPrefixedFrames(max_payload=32)
        second = LengthPrefixedFrames(max_payload=32)
        a = first.encode(b"alpha")
        b = second.encode(b"beta")
        self.assertEqual(first.feed(a[:3]), [])
        self.assertEqual(second.feed(b), [b"beta"])
        self.assertEqual(first.feed(a[3:]), [b"alpha"])
        self.assertEqual(second.feed(second.encode(b"again")), [b"again"])

    def test_bad_header_resets_decoder_before_next_valid_frame(self):
        decoder = LengthPrefixedFrames(max_payload=4)
        with self.assertRaises(FrameError):
            decoder.feed(b"\xff\xff\xff\xff")
        self.assertEqual(decoder.feed(decoder.encode(b"safe")), [b"safe"])

    def test_boundary_payload_and_empty_frame(self):
        decoder = LengthPrefixedFrames(max_payload=4)
        stream = decoder.encode(b"abcd") + decoder.encode(b"")
        self.assertEqual(decoder.feed(stream), [b"abcd", b""])


if __name__ == "__main__":
    unittest.main()
