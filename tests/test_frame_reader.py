"""Tests for generic callback-driven framing; no AOW header is assumed."""
import unittest

from server.frame_reader import (
    CallbackFrameReader,
    FrameProbeLimitExceeded,
    FrameTooLarge,
    InvalidFrameSize,
    TruncatedFrame,
)


def one_byte_synthetic_probe(prefix):
    """Test-only synthetic format: first byte is body length."""
    if not prefix:
        return None
    return prefix[0] + 1


class CallbackFrameReaderTests(unittest.TestCase):
    def test_fragmented_frame_waits_without_consuming(self):
        reader = CallbackFrameReader(one_byte_synthetic_probe)
        reader.feed(b"\x03a")
        self.assertIsNone(reader.read_frame())
        self.assertEqual(reader.available, 2)
        reader.feed(b"bc")
        self.assertEqual(reader.read_frame(), b"\x03abc")
        self.assertEqual(reader.available, 0)

    def test_coalesced_frames_are_returned_one_at_a_time(self):
        reader = CallbackFrameReader(one_byte_synthetic_probe)
        reader.feed(b"\x01A\x02BC")
        self.assertEqual(reader.read_frame(), b"\x01A")
        self.assertEqual(reader.read_frame(), b"\x02BC")
        self.assertIsNone(reader.read_frame())

    def test_partial_body_at_eof_reports_expected_size_without_consuming(self):
        reader = CallbackFrameReader(one_byte_synthetic_probe)
        reader.feed(b"\x03a")
        reader.close()
        with self.assertRaises(TruncatedFrame) as caught:
            reader.read_frame()
        self.assertEqual((caught.exception.expected, caught.exception.available), (4, 2))
        self.assertEqual(reader.available, 2)

    def test_incomplete_prefix_at_eof_is_reported(self):
        def two_byte_probe(prefix):
            if len(prefix) < 2:
                return None
            return int.from_bytes(prefix[:2], "big") + 2

        reader = CallbackFrameReader(two_byte_probe, max_probe_bytes=2)
        reader.feed(b"\x00")
        self.assertIsNone(reader.read_frame())
        reader.close()
        with self.assertRaises(TruncatedFrame) as caught:
            reader.read_frame()
        self.assertIsNone(caught.exception.expected)
        self.assertEqual(caught.exception.available, 1)

    def test_oversized_frame_is_rejected_without_consuming(self):
        reader = CallbackFrameReader(
            one_byte_synthetic_probe,
            max_frame_bytes=8,
            max_buffer_bytes=16,
        )
        reader.feed(b"\xff")
        with self.assertRaises(FrameTooLarge) as caught:
            reader.read_frame()
        self.assertEqual((caught.exception.requested, caught.exception.limit), (256, 8))
        self.assertEqual(reader.available, 1)

    def test_invalid_probe_sizes_are_rejected(self):
        for value in (0, -1, True, 1.5, "4"):
            with self.subTest(value=repr(value)):
                reader = CallbackFrameReader(lambda _prefix, result=value: result)
                reader.feed(b"x")
                with self.assertRaises(InvalidFrameSize):
                    reader.read_frame()
                self.assertEqual(reader.available, 1)

    def test_probe_limit_prevents_unbounded_header_wait(self):
        reader = CallbackFrameReader(
            lambda _prefix: None,
            max_probe_bytes=2,
            max_buffer_bytes=8,
        )
        reader.feed(b"ab")
        with self.assertRaises(FrameProbeLimitExceeded) as caught:
            reader.read_frame()
        self.assertEqual((caught.exception.available, caught.exception.limit), (2, 2))
        self.assertEqual(reader.available, 2)

    def test_probe_exception_does_not_consume_input(self):
        def broken_probe(_prefix):
            raise RuntimeError("synthetic probe failure")

        reader = CallbackFrameReader(broken_probe)
        reader.feed(b"abc")
        with self.assertRaisesRegex(RuntimeError, "synthetic probe failure"):
            reader.read_frame()
        self.assertEqual(reader.available, 3)

    def test_invalid_limits_are_rejected(self):
        for kwargs in (
            {"max_frame_bytes": 0},
            {"max_buffer_bytes": True},
            {"max_probe_bytes": -1},
            {"max_frame_bytes": 9, "max_buffer_bytes": 8},
            {"max_probe_bytes": 9, "max_buffer_bytes": 8},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                CallbackFrameReader(one_byte_synthetic_probe, **kwargs)

        with self.assertRaises(TypeError):
            CallbackFrameReader(None)


if __name__ == "__main__":
    unittest.main()
