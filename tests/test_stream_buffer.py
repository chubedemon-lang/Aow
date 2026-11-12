"""Tests for generic byte-stream buffering, not an AOW frame decoder."""
import unittest

from server.stream_buffer import (
    BoundedStreamBuffer,
    BufferLimitExceeded,
    NeedMoreData,
    StreamClosedError,
    UnexpectedStreamEOF,
)


class BoundedStreamBufferTests(unittest.TestCase):
    def test_fragmented_input_is_read_only_after_complete(self):
        buffer = BoundedStreamBuffer(max_buffer_bytes=8)
        self.assertEqual(buffer.feed(b"ab"), 2)
        with self.assertRaises(NeedMoreData) as caught:
            buffer.read_exact(4)
        self.assertEqual((caught.exception.needed, caught.exception.available), (4, 2))
        self.assertEqual(buffer.available, 2)
        buffer.feed(b"cd")
        self.assertEqual(buffer.read_exact(4), b"abcd")
        self.assertEqual(buffer.available, 0)

    def test_coalesced_chunks_can_be_consumed_as_separate_records(self):
        buffer = BoundedStreamBuffer(max_buffer_bytes=16)
        buffer.feed(b"oneTWOthree")
        self.assertEqual(buffer.read_exact(3), b"one")
        self.assertEqual(buffer.read_exact(3), b"TWO")
        self.assertEqual(buffer.read_exact(5), b"three")
        self.assertEqual(buffer.available, 0)

    def test_peek_does_not_consume_and_discard_is_exact(self):
        buffer = BoundedStreamBuffer()
        buffer.feed(b"abcdef")
        self.assertEqual(buffer.peek(3), b"abc")
        self.assertEqual(buffer.available, 6)
        self.assertEqual(buffer.discard(2), 2)
        self.assertEqual(buffer.read_exact(2), b"cd")
        self.assertEqual(buffer.read_available(), b"ef")

    def test_overflow_is_atomic_and_existing_bytes_are_preserved(self):
        buffer = BoundedStreamBuffer(max_buffer_bytes=4)
        buffer.feed(b"abc")
        with self.assertRaises(BufferLimitExceeded) as caught:
            buffer.feed(b"de")
        self.assertEqual(
            (caught.exception.requested, caught.exception.available, caught.exception.limit),
            (2, 3, 4),
        )
        self.assertEqual(buffer.peek(3), b"abc")
        buffer.feed(b"d")
        self.assertEqual(buffer.read_exact(4), b"abcd")

    def test_multibyte_memoryview_capacity_uses_nbytes(self):
        # len(view) is the number of 32-bit elements (2), while nbytes is 8.
        view = memoryview(bytearray(b"abcdefgh")).cast("I")
        self.assertEqual(len(view), 2)
        self.assertEqual(view.nbytes, 8)

        buffer = BoundedStreamBuffer(max_buffer_bytes=8)
        buffer.feed(b"xy")
        with self.assertRaises(BufferLimitExceeded) as caught:
            buffer.feed(view)
        self.assertEqual(
            (caught.exception.requested, caught.exception.available, caught.exception.limit),
            (8, 2, 8),
        )
        self.assertEqual(buffer.read_available(), b"xy")

    def test_multibyte_memoryview_is_snapshotted_as_raw_bytes(self):
        source = bytearray(b"abcdefgh")
        view = memoryview(source).cast("I")
        buffer = BoundedStreamBuffer(max_buffer_bytes=8)
        self.assertEqual(buffer.feed(view), 8)
        source[:] = b"ABCDEFGH"
        self.assertEqual(buffer.read_exact(8), b"abcdefgh")

    def test_close_allows_draining_then_reports_unexpected_eof(self):
        buffer = BoundedStreamBuffer(max_buffer_bytes=4)
        buffer.feed(b"ab")
        buffer.close()
        self.assertTrue(buffer.closed)
        self.assertEqual(buffer.read_exact(2), b"ab")
        with self.assertRaises(UnexpectedStreamEOF) as caught:
            buffer.read_exact(1)
        self.assertEqual((caught.exception.needed, caught.exception.available), (1, 0))
        self.assertEqual(buffer.available, 0)

    def test_close_with_partial_data_does_not_consume_on_short_read(self):
        buffer = BoundedStreamBuffer()
        buffer.feed(b"abc")
        buffer.close()
        with self.assertRaises(UnexpectedStreamEOF):
            buffer.read_exact(4)
        self.assertEqual(buffer.peek(3), b"abc")

    def test_feed_after_close_is_rejected_even_for_empty_chunk(self):
        buffer = BoundedStreamBuffer()
        buffer.close()
        with self.assertRaises(StreamClosedError):
            buffer.feed(b"")
        with self.assertRaises(StreamClosedError):
            buffer.feed(b"x")

    def test_read_available_limit_and_zero(self):
        buffer = BoundedStreamBuffer()
        buffer.feed(b"abcdef")
        self.assertEqual(buffer.read_available(0), b"")
        self.assertEqual(buffer.read_available(2), b"ab")
        self.assertEqual(buffer.read_available(99), b"cdef")

    def test_bytes_like_inputs_are_snapshotted(self):
        source = bytearray(b"abcd")
        buffer = BoundedStreamBuffer()
        buffer.feed(source)
        source[:] = b"WXYZ"
        self.assertEqual(buffer.read_exact(4), b"abcd")

        strided = memoryview(bytearray(b"a-b-c-d"))[::2]
        buffer.feed(strided)
        self.assertEqual(buffer.read_exact(4), b"abcd")

    def test_empty_reads_and_empty_chunks(self):
        buffer = BoundedStreamBuffer()
        self.assertEqual(buffer.feed(b""), 0)
        self.assertEqual(buffer.peek(0), b"")
        self.assertEqual(buffer.read_exact(0), b"")
        self.assertEqual(buffer.read_available(), b"")

    def test_rejects_invalid_constructor_values_and_counts(self):
        for value in (0, -1, True, 1.5, "8", None):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                BoundedStreamBuffer(value)

        buffer = BoundedStreamBuffer()
        for value in (-1, True, 1.5, "1", None):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                buffer.peek(value)
        with self.assertRaises(TypeError):
            buffer.feed("not bytes")

    def test_read_exact_underflow_does_not_partially_consume(self):
        buffer = BoundedStreamBuffer()
        buffer.feed(b"abc")
        with self.assertRaises(NeedMoreData):
            buffer.read_exact(4)
        self.assertEqual(buffer.read_available(), b"abc")


if __name__ == "__main__":
    unittest.main()
