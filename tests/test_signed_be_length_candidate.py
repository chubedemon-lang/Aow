"""Tests for the generic offline signed-BE32 length hypothesis helper."""

import unittest

from server.signed_be_length_candidate import (
    CandidateLengthTooLarge,
    InvalidCandidateLength,
    make_signed_be_length_candidate_probe,
    make_signed_be_length_candidate_reader,
)


def frame(payload, *, prefix=b""):
    return prefix + len(payload).to_bytes(4, "big", signed=True) + payload


class SignedBeLengthCandidateTests(unittest.TestCase):
    def test_offset_zero_reader_handles_fragmented_and_coalesced_frames(self):
        first = frame(b"one")
        second = frame(b"two")
        reader = make_signed_be_length_candidate_reader(
            length_offset=0, max_payload_bytes=32, max_buffer_bytes=64
        )
        reader.feed(first[:2])
        self.assertIsNone(reader.read_frame())
        reader.feed(first[2:] + second)
        self.assertEqual(reader.read_frame(), first)
        self.assertEqual(reader.read_frame(), second)
        self.assertIsNone(reader.read_frame())
        reader.close()

    def test_offset_four_reader_keeps_pre_length_bytes_opaque(self):
        first = frame(b"payload", prefix=b"ABCD")
        reader = make_signed_be_length_candidate_reader(
            length_offset=4, max_payload_bytes=32, max_buffer_bytes=64
        )
        reader.feed(first[:7])
        self.assertIsNone(reader.read_frame())
        reader.feed(first[7:])
        self.assertEqual(reader.read_frame(), first)
        reader.close()

    def test_probe_waits_for_selected_length_field(self):
        probe = make_signed_be_length_candidate_probe(
            length_offset=4, max_payload_bytes=16
        )
        self.assertIsNone(probe(b"abcd"))
        self.assertEqual(probe(b"abcd" + b"\x00\x00\x00\x02"), 10)

    def test_negative_signed_length_is_rejected(self):
        probe = make_signed_be_length_candidate_probe(
            length_offset=0, max_payload_bytes=16
        )
        with self.assertRaises(InvalidCandidateLength):
            probe(b"\xff\xff\xff\xff")

    def test_oversized_length_is_rejected(self):
        probe = make_signed_be_length_candidate_probe(
            length_offset=0, max_payload_bytes=3
        )
        with self.assertRaises(CandidateLengthTooLarge):
            probe(b"\x00\x00\x00\x04")

    def test_reader_shrinks_payload_bound_to_buffer_capacity(self):
        reader = make_signed_be_length_candidate_reader(
            length_offset=4, max_payload_bytes=100, max_buffer_bytes=12
        )
        reader.feed(b"tag!" + b"\x00\x00\x00\x05")
        with self.assertRaises(CandidateLengthTooLarge) as caught:
            reader.read_frame()
        self.assertEqual(caught.exception.limit, 4)

    def test_rejects_invalid_offsets_and_boolean_values(self):
        for value in (True, False, -1, 1, 8, "0"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    make_signed_be_length_candidate_probe(
                        length_offset=value, max_payload_bytes=1
                    )

    def test_rejects_invalid_limits_and_small_buffers(self):
        for value in (True, -1, 0x80000000, "4"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    make_signed_be_length_candidate_probe(
                        length_offset=0, max_payload_bytes=value
                    )
        with self.assertRaisesRegex(ValueError, "at least 8"):
            make_signed_be_length_candidate_reader(
                length_offset=4, max_payload_bytes=1, max_buffer_bytes=7
            )
        with self.assertRaises(ValueError):
            make_signed_be_length_candidate_reader(
                length_offset=0, max_payload_bytes=1, max_buffer_bytes=True
            )

    def test_rejects_bytes_subclasses_before_custom_length_hook(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom __len__ must not run")

        probe = make_signed_be_length_candidate_probe(
            length_offset=0, max_payload_bytes=16
        )
        with self.assertRaisesRegex(TypeError, "immutable bytes"):
            probe(HostileBytes(b"\x00\x00\x00\x00"))


if __name__ == "__main__":
    unittest.main()
