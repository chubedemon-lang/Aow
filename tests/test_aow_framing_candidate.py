"""Synthetic tests for the isolated receive-length framing candidate."""
import unittest

from server.aow_framing_candidate import (
    OBSERVED_HTTP_MARKER_VALUE,
    InvalidReceiverLength,
    ReceiverPayloadTooLarge,
    UnsupportedHttpMarkerBranch,
    make_four_byte_length_candidate_probe,
    make_four_byte_length_candidate_reader,
)
from server.frame_reader import CallbackFrameReader, TruncatedFrame
from server.stream_reader import read_next_frame


# Deliberately synthetic override; the default marker is tested separately.
SYNTHETIC_HTTP_MARKER = 0x13572468


def make_probe(limit=32):
    return make_four_byte_length_candidate_probe(
        http_marker_value=SYNTHETIC_HTTP_MARKER,
        max_payload_bytes=limit,
    )


def candidate_frame(payload):
    return len(payload).to_bytes(4, "big", signed=True) + payload


class ReceiverLengthCandidateTests(unittest.TestCase):
    def test_default_marker_matches_static_receiver_http_constant(self):
        self.assertEqual(
            OBSERVED_HTTP_MARKER_VALUE,
            int.from_bytes(b"HTTP", "big", signed=True),
        )
        probe = make_four_byte_length_candidate_probe(max_payload_bytes=32)
        with self.assertRaises(UnsupportedHttpMarkerBranch) as caught:
            probe(b"HTTP")
        self.assertEqual(caught.exception.marker_value, OBSERVED_HTTP_MARKER_VALUE)

    def test_probe_waits_until_all_four_prefix_bytes_are_available(self):
        probe = make_probe()
        for prefix in (b"", b"\x00", b"\x00\x00", b"\x00\x00\x00"):
            with self.subTest(prefix=prefix):
                self.assertIsNone(probe(prefix))

    def test_probe_returns_prefix_plus_signed_big_endian_payload_count(self):
        probe = make_probe()
        self.assertEqual(probe(b"\x00\x00\x00\x03ignored"), 7)
        self.assertEqual(probe(b"\x00\x00\x00\x00"), 4)

    def test_negative_signed_count_is_rejected(self):
        with self.assertRaises(InvalidReceiverLength) as caught:
            make_probe()(b"\xff\xff\xff\xff")
        self.assertEqual(caught.exception.length, -1)

    def test_http_marker_branch_is_rejected_without_guessing_its_format(self):
        with self.assertRaises(UnsupportedHttpMarkerBranch) as caught:
            make_probe()(SYNTHETIC_HTTP_MARKER.to_bytes(4, "big"))
        self.assertEqual(caught.exception.marker_value, SYNTHETIC_HTTP_MARKER)

    def test_oversized_count_is_rejected(self):
        with self.assertRaises(ReceiverPayloadTooLarge) as caught:
            make_probe(limit=8)(b"\x00\x00\x00\x09")
        self.assertEqual((caught.exception.requested, caught.exception.limit), (9, 8))

    def test_factory_rejects_invalid_marker_and_limits(self):
        for marker, limit in (
            (True, 8),
            (1 << 31, 8),
            (0, -1),
            (0, True),
            (0, 1 << 31),
        ):
            with self.subTest(marker=marker, limit=limit), self.assertRaises(ValueError):
                make_four_byte_length_candidate_probe(
                    http_marker_value=marker, max_payload_bytes=limit
                )

    def test_probe_rejects_mutable_or_non_bytes_prefixes(self):
        probe = make_probe()
        for prefix in (bytearray(b"\x00\x00\x00\x00"), memoryview(b"\x00\x00\x00\x00"), "data"):
            with self.subTest(prefix=type(prefix).__name__), self.assertRaises(TypeError):
                probe(prefix)

    def test_callback_reader_handles_fragmented_candidate_frame(self):
        reader = CallbackFrameReader(
            make_probe(),
            max_frame_bytes=36,
            max_buffer_bytes=64,
            max_probe_bytes=4,
        )
        reader.feed(b"\x00\x00")
        self.assertIsNone(reader.read_frame())
        reader.feed(b"\x00\x03ab")
        self.assertIsNone(reader.read_frame())
        reader.feed(b"c")
        self.assertEqual(reader.read_frame(), candidate_frame(b"abc"))
        self.assertEqual(reader.available, 0)

    def test_callback_reader_drains_coalesced_candidate_frames(self):
        reader = CallbackFrameReader(
            make_probe(),
            max_frame_bytes=36,
            max_buffer_bytes=64,
            max_probe_bytes=4,
        )
        first = candidate_frame(b"A")
        second = candidate_frame(b"BC")
        reader.feed(first + second)
        self.assertEqual(reader.read_frame(), first)
        self.assertEqual(reader.read_frame(), second)
        self.assertIsNone(reader.read_frame())

    def test_eof_reports_truncated_candidate_body_without_consuming_it(self):
        reader = CallbackFrameReader(
            make_probe(),
            max_frame_bytes=36,
            max_buffer_bytes=64,
            max_probe_bytes=4,
        )
        reader.feed(b"\x00\x00\x00\x03a")
        reader.close()
        with self.assertRaises(TruncatedFrame) as caught:
            reader.read_frame()
        self.assertEqual((caught.exception.expected, caught.exception.available), (7, 5))
        self.assertEqual(reader.available, 5)

    def test_marker_error_preserves_buffered_input(self):
        reader = CallbackFrameReader(
            make_probe(),
            max_frame_bytes=36,
            max_buffer_bytes=64,
            max_probe_bytes=4,
        )
        marker = SYNTHETIC_HTTP_MARKER.to_bytes(4, "big")
        reader.feed(marker + b"tail")
        with self.assertRaises(UnsupportedHttpMarkerBranch):
            reader.read_frame()
        self.assertEqual(reader.available, 8)


    def test_reader_factory_uses_four_byte_probe_and_buffer_derived_frame_limit(self):
        reader = make_four_byte_length_candidate_reader(
            max_payload_bytes=32, max_buffer_bytes=8,
            http_marker_value=SYNTHETIC_HTTP_MARKER,
        )
        reader.feed(b"\\x00\\x00\\x00")
        self.assertIsNone(reader.read_frame())
        reader.feed(b"\\x01A")
        self.assertEqual(reader.read_frame(), candidate_frame(b"A"))
        self.assertEqual(reader.max_frame_bytes, 8)

    def test_reader_factory_caps_payload_to_buffer_space_after_prefix(self):
        reader = make_four_byte_length_candidate_reader(
            max_payload_bytes=32, max_buffer_bytes=6,
            http_marker_value=SYNTHETIC_HTTP_MARKER,
        )
        reader.feed(b"\\x00\\x00\\x00\\x03")
        with self.assertRaises(ReceiverPayloadTooLarge) as caught:
            reader.read_frame()
        self.assertEqual((caught.exception.requested, caught.exception.limit), (3, 2))
        self.assertEqual(reader.available, 4)

    def test_reader_factory_rejects_buffer_smaller_than_prefix(self):
        for value in (True, 3, 3.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                make_four_byte_length_candidate_reader(
                    max_payload_bytes=8, max_buffer_bytes=value,
                    http_marker_value=SYNTHETIC_HTTP_MARKER,
                )

    def test_stream_adapter_reads_fragmented_candidate_frame(self):
        reader = make_four_byte_length_candidate_reader(
            max_payload_bytes=32, max_buffer_bytes=64,
            http_marker_value=SYNTHETIC_HTTP_MARKER,
        )
        chunks = iter((b"\\x00", b"\\x00\\x00", b"\\x03ab", b"c"))
        requests = []

        def recv(size):
            requests.append(size)
            return next(chunks)

        self.assertEqual(
            read_next_frame(reader, recv, max_chunk_bytes=8),
            candidate_frame(b"abc"),
        )
        self.assertEqual(len(requests), 4)
        self.assertEqual(reader.available, 0)

    def test_stream_adapter_drains_coalesced_candidate_frames_without_extra_receive(self):
        reader = make_four_byte_length_candidate_reader(
            max_payload_bytes=32, max_buffer_bytes=64,
            http_marker_value=SYNTHETIC_HTTP_MARKER,
        )
        first = candidate_frame(b"A")
        second = candidate_frame(b"BC")
        calls = []

        def recv(size):
            calls.append(size)
            return first + second

        self.assertEqual(read_next_frame(reader, recv), first)
        self.assertEqual(
            read_next_frame(reader, lambda _size: self.fail("unexpected receive")),
            second,
        )
        self.assertEqual(calls, [64])
        self.assertEqual(reader.available, 0)

    def test_stream_adapter_preserves_truncated_candidate_at_eof(self):
        reader = make_four_byte_length_candidate_reader(
            max_payload_bytes=32, max_buffer_bytes=64,
            http_marker_value=SYNTHETIC_HTTP_MARKER,
        )
        chunks = iter((b"\\x00\\x00\\x00\\x03a", b""))
        with self.assertRaises(TruncatedFrame) as caught:
            read_next_frame(reader, lambda _size: next(chunks))
        self.assertEqual((caught.exception.expected, caught.exception.available), (7, 5))
        self.assertEqual(reader.available, 5)
        self.assertTrue(reader.closed)

    def test_stream_adapter_rejects_static_http_marker_without_consuming_input(self):
        reader = make_four_byte_length_candidate_reader(
            max_payload_bytes=32, max_buffer_bytes=64
        )
        with self.assertRaises(UnsupportedHttpMarkerBranch) as caught:
            read_next_frame(reader, lambda _size: b"HTTPtail")
        self.assertEqual(caught.exception.marker_value, OBSERVED_HTTP_MARKER_VALUE)
        self.assertEqual(reader.available, 8)


if __name__ == "__main__":
    unittest.main()
