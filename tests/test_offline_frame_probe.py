"""Synthetic-only frame probe tests; no AOW packet assumptions."""
import unittest

from server.offline_frame_probe import FrameSpec, LengthFrameDecoder, FrameDecodeError


class OfflineFrameProbeTests(unittest.TestCase):
    def test_fragmented_header_and_body(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "big"))
        self.assertEqual(decoder.feed(b"\x00"), [])
        self.assertEqual(decoder.feed(b"\x03a"), [])
        self.assertEqual(decoder.feed(b"bc"), [b"abc"])
        decoder.finish()

    def test_coalesced_frames_and_partial_tail(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "little"))
        self.assertEqual(decoder.feed(b"\x01A\x02B"), [b"A"])
        self.assertEqual(decoder.feed(b"C"), [b"BC"])
        decoder.finish()

    def test_little_endian_header_included(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "little", includes_header=True))
        self.assertEqual(decoder.feed(b"\x05\x00abc"), [b"abc"])

    def test_zero_length_frame(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        self.assertEqual(decoder.feed(b"\x00\x01x"), [b"", b"x"])

    def test_explicit_zero_payload_cap_accepts_only_empty_frames(self):
        cases = (
            (FrameSpec(1, "big", max_payload=0), b"\x00"),
            (
                FrameSpec(2, "big", includes_header=True, max_payload=0),
                b"\x00\x02",
            ),
        )
        for spec, encoded in cases:
            with self.subTest(spec=spec):
                decoder = LengthFrameDecoder(spec)
                self.assertEqual(decoder.feed(encoded), [b""])
                decoder.finish()

        decoder = LengthFrameDecoder(FrameSpec(1, "big", max_payload=0))
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x01")

    def test_reject_oversize_and_poison_decoder(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "big", max_payload=3))
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x00\x04")
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x00\x01a")

    def test_reject_header_smaller_than_declared_inclusive(self):
        decoder = LengthFrameDecoder(FrameSpec(2, "big", includes_header=True))
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x00\x01")

    def test_truncation(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        decoder.feed(b"\x02a")
        with self.assertRaises(FrameDecodeError):
            decoder.finish()

    def test_oversized_feed_is_rejected_before_buffering_and_poisoned(self):
        decoder = LengthFrameDecoder(
            FrameSpec(1, "big", max_payload=8, max_chunk_bytes=3)
        )
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x02abc")
        self.assertEqual(decoder.pending_bytes, 0)
        with self.assertRaises(FrameDecodeError):
            decoder.feed(b"\x01x")

    def test_fragmented_frame_can_exceed_per_feed_limit(self):
        decoder = LengthFrameDecoder(
            FrameSpec(1, "big", max_payload=8, max_chunk_bytes=3)
        )
        self.assertEqual(decoder.feed(b"\x04a"), [])
        self.assertEqual(decoder.feed(b"bc"), [])
        self.assertEqual(decoder.feed(b"d"), [b"abcd"])
        decoder.finish()

    def test_invalid_chunk_limits(self):
        for value in (True, 0, -1, 16 * 1024 * 1024 + 1, "4"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                FrameSpec(1, "big", max_chunk_bytes=value)

    def test_default_payload_cap_fits_length_field(self):
        self.assertEqual(FrameSpec(1, "big").max_payload, 255)
        self.assertEqual(
            FrameSpec(1, "big", includes_header=True).max_payload, 254
        )
        self.assertEqual(FrameSpec(2, "big").max_payload, 65535)
        self.assertEqual(
            FrameSpec(2, "big", includes_header=True).max_payload, 65533
        )
        self.assertEqual(FrameSpec(4, "big").max_payload, 1024 * 1024)

    def test_payload_limit_must_fit_length_field(self):
        valid_specs = (
            (1, False, 255),
            (1, True, 254),
            (2, False, 65535),
            (2, True, 65533),
            (4, False, 16 * 1024 * 1024),
        )
        for length_bytes, includes_header, max_payload in valid_specs:
            with self.subTest(length_bytes=length_bytes,
                              includes_header=includes_header,
                              max_payload=max_payload):
                FrameSpec(length_bytes, "big", includes_header, max_payload)

        invalid_specs = (
            (1, False, 256),
            (1, True, 255),
            (2, False, 65536),
            (2, True, 65534),
        )
        for length_bytes, includes_header, max_payload in invalid_specs:
            with self.subTest(length_bytes=length_bytes,
                              includes_header=includes_header,
                              max_payload=max_payload):
                with self.assertRaisesRegex(ValueError, "unrepresentable"):
                    FrameSpec(length_bytes, "big", includes_header, max_payload)

    def test_reject_unbounded_or_ambiguous_config(self):
        for args in ((3, "big"), (2, "middle")):
            with self.assertRaises(ValueError):
                FrameSpec(*args)
        self.assertEqual(FrameSpec(2, "big", max_payload=0).max_payload, 0)
        with self.assertRaises(TypeError):
            LengthFrameDecoder(None)
        with self.assertRaises(TypeError):
            LengthFrameDecoder(FrameSpec(1, "big")).feed(bytearray(b"\x01a"))

    def test_clean_eof_is_terminal(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        self.assertEqual(decoder.feed(b"\x01x"), [b"x"])
        decoder.finish()
        self.assertEqual(decoder.pending_bytes, 0)
        with self.assertRaisesRegex(FrameDecodeError, "already finished"):
            decoder.feed(b"\x01y")
        with self.assertRaisesRegex(FrameDecodeError, "already finished"):
            decoder.finish()

    def test_truncated_eof_discards_pending_and_is_terminal(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        decoder.feed(b"\x03ab")
        self.assertEqual(decoder.pending_bytes, 3)
        with self.assertRaisesRegex(FrameDecodeError, "truncated final frame"):
            decoder.finish()
        self.assertEqual(decoder.pending_bytes, 0)
        with self.assertRaisesRegex(FrameDecodeError, "failed"):
            decoder.feed(b"c")

    def test_frame_flood_exceeds_per_feed_limit_and_poison_decoder(self):
        decoder = LengthFrameDecoder(
            FrameSpec(1, "big", max_frames_per_feed=2)
        )
        with self.assertRaisesRegex(FrameDecodeError, "frame count"):
            decoder.feed(b"\x00\x00\x00")
        self.assertEqual(decoder.pending_bytes, 0)
        with self.assertRaisesRegex(FrameDecodeError, "failed"):
            decoder.feed(b"\x00")

    def test_exact_frame_count_limit_is_allowed_per_feed(self):
        decoder = LengthFrameDecoder(
            FrameSpec(1, "big", max_frames_per_feed=2)
        )
        self.assertEqual(decoder.feed(b"\x00\x00\x01"), [b"", b""])
        self.assertEqual(decoder.pending_bytes, 1)
        self.assertEqual(decoder.feed(b"x"), [b"x"])
        decoder.finish()

    def test_invalid_frame_count_limits(self):
        for value in (True, 0, -1, 65537, "2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                FrameSpec(1, "big", max_frames_per_feed=value)
        self.assertEqual(FrameSpec(1, "big", max_frames_per_feed=1).max_frames_per_feed, 1)
        self.assertEqual(
            FrameSpec(1, "big", max_frames_per_feed=65536).max_frames_per_feed,
            65536,
        )

    def test_rejects_bytes_subclass_before_length_or_bytes_hooks(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom __len__ must not run")

            def __bytes__(self):
                raise AssertionError("custom __bytes__ must not run")

        decoder = LengthFrameDecoder(FrameSpec(1, "big"))
        with self.assertRaisesRegex(TypeError, "exact built-in bytes"):
            decoder.feed(HostileBytes(b"\x01x"))
        self.assertEqual(decoder.pending_bytes, 0)

    def test_rejects_string_subclass_for_byteorder_before_comparison(self):
        class HostileByteorder(str):
            def __eq__(self, other):
                raise AssertionError("custom __eq__ must not run")

        with self.assertRaisesRegex(ValueError, "exact string"):
            FrameSpec(1, HostileByteorder("big"))

    def test_decoder_snapshots_validated_spec_at_construction(self):
        spec = FrameSpec(1, "big", max_payload=2, max_chunk_bytes=3)
        decoder = LengthFrameDecoder(spec)

        object.__setattr__(spec, "max_payload", 8)
        object.__setattr__(spec, "max_chunk_bytes", 8)

        with self.assertRaisesRegex(FrameDecodeError, "invalid declared frame size"):
            decoder.feed(b"\x03")

    def test_decoder_spec_property_returns_detached_copy(self):
        decoder = LengthFrameDecoder(FrameSpec(1, "big", max_payload=2))
        exposed = decoder.spec
        object.__setattr__(exposed, "max_payload", 8)

        with self.assertRaisesRegex(FrameDecodeError, "invalid declared frame size"):
            decoder.feed(b"\x03")

    def test_decoder_revalidates_mutated_spec_before_use(self):
        spec = FrameSpec(1, "big", max_payload=2)
        object.__setattr__(spec, "max_payload", -1)

        with self.assertRaisesRegex(ValueError, "max_payload"):
            LengthFrameDecoder(spec)

    def test_decoder_rejects_spec_with_deleted_configuration(self):
        spec = FrameSpec(1, "big")
        object.__delattr__(spec, "max_chunk_bytes")

        with self.assertRaisesRegex(TypeError, "intact FrameSpec"):
            LengthFrameDecoder(spec)

    def test_rejects_frame_spec_subclasses(self):
        class ExtendedFrameSpec(FrameSpec):
            pass

        with self.assertRaisesRegex(TypeError, "exact FrameSpec"):
            ExtendedFrameSpec(1, "big")


if __name__ == "__main__":
    unittest.main()
