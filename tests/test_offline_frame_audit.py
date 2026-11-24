"""Synthetic-only tests for the payload-free offline frame audit."""
import hashlib
import unittest

from server.offline_frame_probe import FrameDecodeError, FrameSpec
from server.offline_frame_audit import (
    OfflineFrameAuditError,
    audit_packet_fixture_frames,
)


SOURCE_SHA256 = "a" * 64


def fixture(payload):
    return {
        "source_sha256": SOURCE_SHA256,
        "payload_hex": payload.hex(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "verified": True,
    }


def encode(payloads, spec):
    frames = []
    for payload in payloads:
        declared = len(payload) + (
            spec.length_bytes if spec.includes_header else 0
        )
        frames.append(
            declared.to_bytes(spec.length_bytes, spec.byteorder) + payload
        )
    return b"".join(frames)


class OfflineFrameAuditTests(unittest.TestCase):
    def test_fragmented_fixture_returns_only_frame_metadata(self):
        spec = FrameSpec(2, "big", max_payload=32)
        wire = encode((b"alpha", b"beta"), spec)
        result = audit_packet_fixture_frames(
            fixture(wire),
            expected_source_sha256=SOURCE_SHA256,
            spec=spec,
            chunk_size=3,
        )
        self.assertEqual(result.source_sha256, SOURCE_SHA256)
        self.assertEqual(result.fixture_sha256, hashlib.sha256(wire).hexdigest())
        self.assertEqual(result.frame_count, 2)
        self.assertEqual(result.wire_bytes, len(wire))
        self.assertEqual(result.header_bytes, 4)
        self.assertEqual(result.payload_bytes, 9)
        self.assertEqual(result.payload_sizes, (5, 4))
        self.assertEqual(result.frame_spans, ((0, 2, 7), (7, 9, 13)))
        self.assertEqual(
            result.payload_sha256,
            (hashlib.sha256(b"alpha").hexdigest(),
             hashlib.sha256(b"beta").hexdigest()),
        )
        self.assertNotIn(b"alpha", repr(result).encode())
        self.assertFalse(hasattr(result, "payloads"))

    def test_header_inclusive_little_endian_fixture(self):
        spec = FrameSpec(2, "little", includes_header=True, max_payload=16)
        wire = encode((b"", b"x", b"yz"), spec)
        result = audit_packet_fixture_frames(
            fixture(wire),
            expected_source_sha256=SOURCE_SHA256,
            spec=spec,
        )
        self.assertEqual(result.frame_count, 3)
        self.assertEqual(result.header_bytes, 6)
        self.assertEqual(result.payload_bytes, 3)
        self.assertEqual(result.wire_bytes, 9)
        self.assertEqual(result.payload_sizes, (0, 1, 2))
        self.assertEqual(
            result.frame_spans,
            ((0, 2, 2), (2, 4, 5), (5, 7, 9)),
        )


    def test_frame_spans_are_zero_based_and_end_exclusive_across_fragments(self):
        spec = FrameSpec(1, "big", max_payload=8)
        wire = encode((b"", b"a", b"bc"), spec)
        result = audit_packet_fixture_frames(
            fixture(wire),
            expected_source_sha256=SOURCE_SHA256,
            spec=spec,
            chunk_size=1,
        )
        self.assertEqual(
            result.frame_spans,
            ((0, 1, 1), (1, 2, 3), (3, 4, 6)),
        )
        self.assertEqual(result.frame_spans[-1][2], result.wire_bytes)

    def test_empty_fixture_produces_empty_complete_summary(self):
        spec = FrameSpec(4, "big")
        result = audit_packet_fixture_frames(
            fixture(b""),
            expected_source_sha256=SOURCE_SHA256,
            spec=spec,
        )
        self.assertEqual(
            (result.frame_count, result.wire_bytes, result.payload_bytes),
            (0, 0, 0),
        )
        self.assertEqual(
            result.fixture_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(result.payload_sizes, ())
        self.assertEqual(result.payload_sha256, ())
        self.assertEqual(result.frame_spans, ())

    def test_rejects_fixture_from_different_source_before_decoding(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            audit_packet_fixture_frames(
                fixture(b""),
                expected_source_sha256="b" * 64,
                spec=FrameSpec(1, "big"),
            )

    def test_truncated_fixture_does_not_return_partial_summary(self):
        spec = FrameSpec(1, "big", max_payload=8)
        with self.assertRaises(FrameDecodeError):
            audit_packet_fixture_frames(
                fixture(b"\x03ab"),
                expected_source_sha256=SOURCE_SHA256,
                spec=spec,
                chunk_size=1,
            )

    def test_oversized_declared_frame_is_rejected(self):
        spec = FrameSpec(1, "big", max_payload=2)
        with self.assertRaises(FrameDecodeError):
            audit_packet_fixture_frames(
                fixture(b"\x03abc"),
                expected_source_sha256=SOURCE_SHA256,
                spec=spec,
            )

    def test_global_frame_count_limit_applies_across_chunks(self):
        spec = FrameSpec(1, "big", max_payload=0, max_frames_per_feed=16)
        with self.assertRaises(OfflineFrameAuditError):
            audit_packet_fixture_frames(
                fixture(b"\x00\x00\x00"),
                expected_source_sha256=SOURCE_SHA256,
                spec=spec,
                chunk_size=1,
                max_frames=2,
            )

    def test_rejects_invalid_limits_and_chunk_size(self):
        spec = FrameSpec(1, "big", max_chunk_bytes=4)
        for value in (True, 0, -1, 65537, "2"):
            with self.subTest(max_frames=value), self.assertRaises(ValueError):
                audit_packet_fixture_frames(
                    fixture(b""),
                    expected_source_sha256=SOURCE_SHA256,
                    spec=spec,
                    max_frames=value,
                )
        for value in (True, 0, 1048577, "4"):
            with self.subTest(max_fixture_bytes=value), self.assertRaises(ValueError):
                audit_packet_fixture_frames(
                    fixture(b""),
                    expected_source_sha256=SOURCE_SHA256,
                    spec=spec,
                    max_fixture_bytes=value,
                )
        for value in (True, 0, 5, "2"):
            with self.subTest(chunk_size=value), self.assertRaises(ValueError):
                audit_packet_fixture_frames(
                    fixture(b""),
                    expected_source_sha256=SOURCE_SHA256,
                    spec=spec,
                    chunk_size=value,
                )

    def test_rejects_damaged_frame_spec_before_fixture_validation(self):
        spec = FrameSpec(1, "big", max_payload=2)
        object.__setattr__(spec, "max_payload", -1)
        with self.assertRaisesRegex(ValueError, "max_payload"):
            audit_packet_fixture_frames(
                {"not": "a fixture"},
                expected_source_sha256=SOURCE_SHA256,
                spec=spec,
            )


if __name__ == "__main__":
    unittest.main()
