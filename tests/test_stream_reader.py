"""Tests for the generic blocking stream receive adapter; no AOW format."""
import unittest

from server.frame_reader import CallbackFrameReader, TruncatedFrame
from server.stream_reader import (
    InvalidReadChunk,
    ReadBufferFull,
    read_next_frame,
)


def one_byte_synthetic_probe(prefix):
    """Test-only format: first byte is body length."""
    if not prefix:
        return None
    return prefix[0] + 1


def make_reader(*, max_buffer_bytes=64):
    return CallbackFrameReader(
        one_byte_synthetic_probe,
        max_frame_bytes=max_buffer_bytes,
        max_buffer_bytes=max_buffer_bytes,
        max_probe_bytes=1,
    )


class StreamReaderTests(unittest.TestCase):
    def test_reads_fragmented_frame_until_complete(self):
        chunks = iter((b"\x03a", b"b", b"c"))
        requests = []

        def recv(size):
            requests.append(size)
            return next(chunks)

        reader = make_reader()
        self.assertEqual(
            read_next_frame(reader, recv, max_chunk_bytes=8),
            b"\x03abc",
        )
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(1 <= size <= 8 for size in requests))
        self.assertEqual(reader.available, 0)

    def test_coalesced_frames_are_drained_without_an_extra_receive(self):
        first = b"\x01A"
        second = b"\x02BC"
        calls = []

        def recv(size):
            calls.append(size)
            return first + second

        reader = make_reader()
        self.assertEqual(read_next_frame(reader, recv), first)
        self.assertEqual(
            read_next_frame(reader, lambda _size: self.fail("unexpected recv")),
            second,
        )
        self.assertEqual(calls, [64])
        self.assertEqual(reader.available, 0)

    def test_retries_interrupted_receive_without_losing_buffered_prefix(self):
        reader = make_reader()
        reader.feed(b"\x02")
        calls = []

        def recv(size):
            calls.append(size)
            if len(calls) == 1:
                raise InterruptedError()
            return b"xy"

        self.assertEqual(read_next_frame(reader, recv), b"\x02xy")
        self.assertEqual(calls, [63, 63])
        self.assertEqual(reader.available, 0)

    def test_receive_request_is_capped_by_remaining_buffer_capacity(self):
        reader = make_reader(max_buffer_bytes=4)
        reader.feed(b"\x02")
        requests = []

        def recv(size):
            requests.append(size)
            return b"ab"

        self.assertEqual(
            read_next_frame(reader, recv, max_chunk_bytes=10),
            b"\x02ab",
        )
        self.assertEqual(requests, [3])

    def test_clean_eof_returns_none_and_closes_reader(self):
        reader = make_reader()
        self.assertIsNone(read_next_frame(reader, lambda _size: b""))
        self.assertTrue(reader.closed)
        self.assertIsNone(
            read_next_frame(reader, lambda _size: self.fail("closed reader received"))
        )

    def test_eof_with_partial_body_raises_and_preserves_buffer(self):
        reader = make_reader()
        reader.feed(b"\x03a")
        with self.assertRaises(TruncatedFrame) as caught:
            read_next_frame(reader, lambda _size: b"")
        self.assertEqual((caught.exception.expected, caught.exception.available), (4, 2))
        self.assertEqual(reader.available, 2)
        self.assertTrue(reader.closed)

    def test_eof_with_partial_prefix_raises_and_preserves_buffer(self):
        def two_byte_probe(prefix):
            if len(prefix) < 2:
                return None
            return int.from_bytes(prefix[:2], "big") + 2

        reader = CallbackFrameReader(
            two_byte_probe,
            max_frame_bytes=8,
            max_buffer_bytes=8,
            max_probe_bytes=2,
        )
        reader.feed(b"\x00")
        with self.assertRaises(TruncatedFrame) as caught:
            read_next_frame(reader, lambda _size: b"")
        self.assertIsNone(caught.exception.expected)
        self.assertEqual(caught.exception.available, 1)
        self.assertEqual(reader.available, 1)

    def test_drains_complete_frame_before_reporting_truncated_coalesced_tail(self):
        reader = make_reader()
        reader.feed(b"\x01A\x03bc")

        self.assertEqual(
            read_next_frame(reader, lambda _size: self.fail("unexpected recv")),
            b"\x01A",
        )
        with self.assertRaises(TruncatedFrame) as caught:
            read_next_frame(reader, lambda _size: b"")

        self.assertEqual((caught.exception.expected, caught.exception.available), (4, 3))
        self.assertEqual(reader.available, 3)
        self.assertTrue(reader.closed)

    def test_closed_reader_drains_complete_frame_before_clean_eof(self):
        reader = make_reader()
        reader.feed(b"\x01A")
        reader.close()

        self.assertEqual(
            read_next_frame(reader, lambda _size: self.fail("closed reader received")),
            b"\x01A",
        )
        self.assertIsNone(
            read_next_frame(reader, lambda _size: self.fail("closed reader received"))
        )

    def test_invalid_receive_types_are_rejected_without_feeding(self):
        for value in (None, bytearray(b"x"), memoryview(b"x"), "x", 1):
            with self.subTest(value=type(value).__name__):
                fresh = make_reader()
                with self.assertRaises(InvalidReadChunk):
                    read_next_frame(fresh, lambda _size, result=value: result)
                self.assertEqual(fresh.available, 0)
                self.assertFalse(fresh.closed)

    def test_overreported_receive_chunk_is_rejected(self):
        reader = make_reader(max_buffer_bytes=4)
        with self.assertRaises(InvalidReadChunk) as caught:
            read_next_frame(reader, lambda _size: b"12345", max_chunk_bytes=4)
        self.assertEqual((caught.exception.received, caught.exception.requested), (5, 4))
        self.assertEqual(reader.available, 0)

    def test_callback_exception_propagates_without_closing_reader(self):
        reader = make_reader()

        def recv(_size):
            raise TimeoutError("synthetic timeout")

        with self.assertRaisesRegex(TimeoutError, "synthetic timeout"):
            read_next_frame(reader, recv)
        self.assertFalse(reader.closed)
        self.assertEqual(reader.available, 0)

    def test_prebuffered_complete_frame_does_not_call_receive(self):
        reader = make_reader()
        reader.feed(b"\x01A")
        self.assertEqual(
            read_next_frame(reader, lambda _size: self.fail("unexpected recv")),
            b"\x01A",
        )

    def test_invalid_arguments_fail_before_receive(self):
        reader = make_reader()
        for value in (True, 0, -1, 1.5, "4"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read_next_frame(
                    reader,
                    lambda _size: self.fail("unexpected recv"),
                    max_chunk_bytes=value,
                )
        with self.assertRaises(TypeError):
            read_next_frame(object(), lambda _size: b"")
        with self.assertRaises(TypeError):
            read_next_frame(reader, None)

    def test_reader_exhaustion_is_reported_without_calling_receive(self):
        class StalledReader(CallbackFrameReader):
            def read_frame(self):
                return None

        # This deliberately violates the base reader's progress contract to
        # exercise the adapter's defensive capacity guard.
        reader = StalledReader(
            one_byte_synthetic_probe,
            max_frame_bytes=4,
            max_buffer_bytes=4,
            max_probe_bytes=1,
        )
        reader.feed(b"abcd")
        with self.assertRaises(ReadBufferFull):
            read_next_frame(reader, lambda _size: self.fail("unexpected recv"))


if __name__ == "__main__":
    unittest.main()
