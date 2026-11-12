"""Tests for generic bounded stream writes; no AOW framing is assumed."""
import array
import unittest

from server.stream_writer import (
    InvalidWriteCount,
    NoWriteProgress,
    PartialWriteError,
    WritePayloadTooLarge,
    write_all,
)


class StreamWriterTests(unittest.TestCase):
    def test_writes_until_all_bytes_are_accepted(self):
        accepted = []

        def send(view):
            count = min(2, len(view))
            accepted.append(bytes(view[:count]))
            return count

        self.assertEqual(write_all(send, b"hello", max_bytes=5), 5)
        self.assertEqual(b"".join(accepted), b"hello")

    def test_retries_interrupted_error_without_advancing_offset(self):
        calls = []

        def send(view):
            calls.append(bytes(view))
            if len(calls) == 1:
                raise InterruptedError()
            return len(view)

        self.assertEqual(write_all(send, b"abc", max_bytes=3), 3)
        self.assertEqual(calls, [b"abc", b"abc"])

    def test_zero_progress_reports_exact_resume_offset(self):
        calls = 0

        def send(view):
            nonlocal calls
            calls += 1
            return 2 if calls == 1 else 0

        with self.assertRaises(PartialWriteError) as caught:
            write_all(send, b"abcde", max_bytes=5)

        error = caught.exception
        self.assertEqual((error.bytes_written, error.total_bytes), (2, 5))
        self.assertIsInstance(error.cause, NoWriteProgress)
        self.assertEqual(b"abcde"[error.bytes_written:], b"cde")

    def test_sink_exception_after_partial_write_preserves_progress(self):
        calls = 0

        def send(view):
            nonlocal calls
            calls += 1
            if calls == 1:
                return 1
            raise BlockingIOError("synthetic would-block")

        with self.assertRaises(PartialWriteError) as caught:
            write_all(send, b"data", max_bytes=4)

        self.assertEqual(caught.exception.bytes_written, 1)
        self.assertEqual(caught.exception.total_bytes, 4)
        self.assertIsInstance(caught.exception.cause, BlockingIOError)

    def test_overreported_count_is_rejected(self):
        with self.assertRaises(PartialWriteError) as caught:
            write_all(lambda view: len(view) + 1, b"x", max_bytes=1)
        self.assertEqual(caught.exception.bytes_written, 0)
        self.assertIsInstance(caught.exception.cause, InvalidWriteCount)

    def test_non_integer_counts_are_rejected(self):
        for value in (True, 1.0, None, "1"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(PartialWriteError) as caught:
                    write_all(lambda _view, result=value: result, b"x", max_bytes=1)
                self.assertIsInstance(caught.exception.cause, InvalidWriteCount)

    def test_negative_and_zero_counts_are_rejected(self):
        for value in (0, -1):
            with self.subTest(value=value):
                with self.assertRaises(PartialWriteError) as caught:
                    write_all(lambda _view, result=value: result, b"x", max_bytes=1)
                self.assertIsInstance(caught.exception.cause, NoWriteProgress)

    def test_size_limit_is_checked_before_calling_sink(self):
        called = []

        def send(view):
            called.append(bytes(view))
            return len(view)

        with self.assertRaises(WritePayloadTooLarge) as caught:
            write_all(send, b"four", max_bytes=3)

        self.assertEqual((caught.exception.requested, caught.exception.limit), (4, 3))
        self.assertEqual(called, [])

    def test_memoryview_limit_uses_nbytes_and_snapshots_logical_bytes(self):
        source = array.array("I", [0x01020304, 0x05060708])
        view = memoryview(source)
        expected = view.tobytes()
        accepted = []

        with self.assertRaises(WritePayloadTooLarge):
            write_all(lambda chunk: len(chunk), view, max_bytes=view.nbytes - 1)

        self.assertEqual(
            write_all(lambda chunk: accepted.append(bytes(chunk)) or len(chunk),
                      view, max_bytes=view.nbytes),
            view.nbytes,
        )
        self.assertEqual(b"".join(accepted), expected)

    def test_mutable_payload_is_snapshotted_before_first_send(self):
        payload = bytearray(b"abc")
        observed = []

        def send(view):
            observed.append(bytes(view))
            payload[:] = b"xyz"
            return len(view)

        self.assertEqual(write_all(send, payload, max_bytes=3), 3)
        self.assertEqual(observed, [b"abc"])

    def test_empty_payload_does_not_call_sink(self):
        called = []
        self.assertEqual(write_all(lambda _view: called.append(True), b"", max_bytes=0), 0)
        self.assertEqual(called, [])

    def test_invalid_arguments_fail_before_writing(self):
        with self.assertRaises(TypeError):
            write_all(None, b"x", max_bytes=1)
        with self.assertRaises(TypeError):
            write_all(lambda _view: 1, "x", max_bytes=1)
        for limit in (True, -1, 1.5):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                write_all(lambda _view: 1, b"x", max_bytes=limit)


if __name__ == "__main__":
    unittest.main()
