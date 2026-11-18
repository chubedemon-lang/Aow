"""Tests for the private, redacted-output stream fixture inspector."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from tools.protocol_fixture_audit import (
    MAX_CANDIDATE_FRAMES,
    MAX_CAPTURE_ELAPSED_NS,
    MAX_JSON_NESTING,
    FixtureAuditError,
    audit_fixture_bytes,
    inspect_fixture_file,
    main,
    _decode_chunks,
)


APK_SHA256 = "a" * 64


def frame(payload):
    return len(payload).to_bytes(4, "big", signed=True) + payload


def fixture_bytes(
    server_chunks,
    client_chunks=(b"\x00",),
    *,
    apk_sha256=APK_SHA256,
    client_unchanged=True,
    capture_kind="authorized_local_runtime",
    schema_version=1,
    io_events=None,
):
    document = {
        "schema_version": schema_version,
        "apk_sha256": apk_sha256,
        "client_unchanged": client_unchanged,
        "capture_kind": capture_kind,
        "streams": {
            "server_to_client": [chunk.hex() for chunk in server_chunks],
            "client_to_server": [chunk.hex() for chunk in client_chunks],
        },
    }
    if schema_version in (2, 3):
        document["io_events"] = io_events
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


class ProtocolFixtureAuditTests(unittest.TestCase):
    def audit(self, content, **kwargs):
        return audit_fixture_bytes(
            content,
            expected_apk_sha256=APK_SHA256,
            **kwargs,
        )

    def test_recovers_receive_candidate_across_fragmented_and_coalesced_chunks(self):
        first = frame(b"A")
        second = frame(b"BC")
        content = fixture_bytes(
            [first[:2], first[2:] + second],
            [b"\x10\x20"],
        )
        result = self.audit(content)

        self.assertEqual(result["status"], "candidate_analysis_only")
        self.assertEqual(result["server_to_client"]["chunk_count"], 2)
        self.assertEqual(result["server_to_client"]["stream_bytes"], len(first + second))
        candidate = result["server_to_client"]["receive_candidate"]
        self.assertEqual(candidate["status"], "candidate_frames_recovered")
        self.assertEqual(candidate["frame_count"], 2)
        self.assertEqual(candidate["frame_sizes"], [len(first), len(second)])
        self.assertEqual(candidate["candidate_bytes_consumed"], len(first + second))
        self.assertEqual(candidate["unclassified_stream_bytes"], 0)
        self.assertTrue(candidate["candidate_stream_fully_consumed"])

    def test_client_to_server_stream_is_summarized_but_not_decoded(self):
        content = fixture_bytes([frame(b"ok")], [b"HTTP", b"tail"])
        result = self.audit(content)

        self.assertEqual(
            result["client_to_server"]["analysis"],
            "not_attempted_sender_symmetry_unproven",
        )
        self.assertEqual(result["client_to_server"]["stream_bytes"], 8)
        self.assertEqual(
            result["server_to_client"]["receive_candidate"]["status"],
            "candidate_frames_recovered",
        )

    def test_static_http_marker_reports_candidate_not_recovered(self):
        result = self.audit(fixture_bytes([b"HTTPresponse"]))
        candidate = result["server_to_client"]["receive_candidate"]

        self.assertEqual(result["status"], "candidate_not_recovered")
        self.assertEqual(candidate["reason"], "UnsupportedHttpMarkerBranch")
        self.assertEqual(candidate["frame_count"], 0)

    def test_partial_candidate_frames_leave_marker_and_tail_unclassified(self):
        complete = frame(b"ok")
        unsupported_tail = b"HTTPresponse"
        result = self.audit(fixture_bytes([complete + unsupported_tail]))
        candidate = result["server_to_client"]["receive_candidate"]

        self.assertEqual(result["status"], "candidate_not_recovered")
        self.assertEqual(candidate["frame_count"], 1)
        self.assertEqual(candidate["candidate_bytes_consumed"], len(complete))
        self.assertEqual(
            candidate["unclassified_stream_bytes"], len(unsupported_tail)
        )
        self.assertFalse(candidate["candidate_stream_fully_consumed"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

    def test_truncated_receive_candidate_is_reported_without_guessing(self):
        result = self.audit(fixture_bytes([frame(b"payload")[:-1]]))
        candidate = result["server_to_client"]["receive_candidate"]

        self.assertEqual(result["status"], "candidate_not_recovered")
        self.assertEqual(candidate["reason"], "TruncatedFrame")
        self.assertEqual(candidate["frame_count"], 0)
        self.assertEqual(candidate["candidate_bytes_consumed"], 0)
        self.assertEqual(
            candidate["unclassified_stream_bytes"], len(frame(b"payload")[:-1])
        )
        self.assertFalse(candidate["candidate_stream_fully_consumed"])

    def test_negative_and_oversized_candidate_lengths_fail_closed(self):
        negative = self.audit(fixture_bytes([b"\xff\xff\xff\xff"]))
        oversized = self.audit(
            fixture_bytes([b"\x00\x00\x00\x05"]),
            max_payload_bytes=4,
            max_buffer_bytes=8,
        )
        self.assertEqual(
            negative["server_to_client"]["receive_candidate"]["reason"],
            "InvalidReceiverLength",
        )
        self.assertEqual(
            oversized["server_to_client"]["receive_candidate"]["reason"],
            "ReceiverPayloadTooLarge",
        )

    def test_candidate_frame_report_has_a_hard_count_cap(self):
        exact_limit_stream = b"".join(
            frame(b"") for _ in range(MAX_CANDIDATE_FRAMES)
        )
        exact_limit = self.audit(fixture_bytes([exact_limit_stream]))
        exact_candidate = exact_limit["server_to_client"]["receive_candidate"]
        self.assertEqual(exact_candidate["status"], "candidate_frames_recovered")
        self.assertEqual(exact_candidate["frame_count"], MAX_CANDIDATE_FRAMES)
        self.assertFalse(exact_candidate["frame_count_is_lower_bound"])
        self.assertFalse(exact_candidate["frame_sizes_truncated"])
        self.assertEqual(len(exact_candidate["frame_sizes"]), MAX_CANDIDATE_FRAMES)

        over_limit_stream = exact_limit_stream + frame(b"")
        over_limit = self.audit(fixture_bytes([over_limit_stream]))
        candidate = over_limit["server_to_client"]["receive_candidate"]
        self.assertEqual(candidate["status"], "candidate_not_recovered")
        self.assertEqual(candidate["reason"], "CandidateFrameCountLimit")
        self.assertEqual(candidate["frame_count"], MAX_CANDIDATE_FRAMES)
        self.assertTrue(candidate["frame_count_is_lower_bound"])
        self.assertTrue(candidate["frame_sizes_truncated"])
        self.assertEqual(len(candidate["frame_sizes"]), MAX_CANDIDATE_FRAMES)
        # The overflow-detection read consumes one additional complete frame.
        # Its size is intentionally omitted from the bounded report, but its
        # bytes must not be mislabeled as unclassified stream data.
        self.assertEqual(candidate["candidate_bytes_consumed"], len(over_limit_stream))
        self.assertEqual(candidate["unclassified_stream_bytes"], 0)
        self.assertTrue(candidate["candidate_stream_fully_consumed"])

    def test_rejects_excessive_json_nesting_before_object_construction(self):
        base = fixture_bytes([frame(b"x")]).decode("utf-8")
        nested = "[" * (MAX_JSON_NESTING + 1) + "0" + "]" * (MAX_JSON_NESTING + 1)
        content = (base[:-1] + ', "extra":' + nested + "}").encode("utf-8")
        with self.assertRaisesRegex(FixtureAuditError, "nesting"):
            self.audit(content)

    def test_json_nesting_scan_ignores_brackets_inside_strings(self):
        base = fixture_bytes([frame(b"x")]).decode("utf-8")
        bracket_text = 'quoted: " ' + "[" * (MAX_JSON_NESTING + 10) + "]" * (MAX_JSON_NESTING + 10)
        content = (base[:-1] + ', "extra":' + json.dumps(bracket_text) + "}").encode("utf-8")
        with self.assertRaisesRegex(FixtureAuditError, "object shape"):
            self.audit(content)

    def test_private_file_reader_normalizes_embedded_nul_path(self):
        with self.assertRaisesRegex(FixtureAuditError, "cannot be inspected safely"):
            inspect_fixture_file("invalid\x00fixture.json", expected_apk_sha256=APK_SHA256)

    def test_fingerprint_must_match_operator_selected_build(self):
        content = fixture_bytes([frame(b"x")], apk_sha256="b" * 64)
        with self.assertRaisesRegex(FixtureAuditError, "does not match"):
            self.audit(content)

    def test_original_client_must_be_asserted_unchanged(self):
        content = fixture_bytes([frame(b"x")], client_unchanged=False)
        with self.assertRaisesRegex(FixtureAuditError, "unchanged"):
            self.audit(content)

    def test_capture_kind_is_restricted_to_authorized_local_sources(self):
        content = fixture_bytes([frame(b"x")], capture_kind="synthetic_test")
        with self.assertRaisesRegex(FixtureAuditError, "capture kind"):
            self.audit(content)

    def test_schema_version_rejects_boolean_and_unknown_fields(self):
        document = json.loads(fixture_bytes([frame(b"x")]))
        document["schema_version"] = True
        with self.assertRaisesRegex(FixtureAuditError, "schema version"):
            self.audit(json.dumps(document).encode())

        document["schema_version"] = 1
        document["endpoint"] = "must-not-be-recorded"
        with self.assertRaisesRegex(FixtureAuditError, "object shape"):
            self.audit(json.dumps(document).encode())

    def test_duplicate_json_keys_are_rejected(self):
        content = (
            b'{"schema_version":1,"schema_version":1,'
            b'"apk_sha256":"' + APK_SHA256.encode() + b'",'
            b'"client_unchanged":true,'
            b'"capture_kind":"authorized_local_runtime",'
            b'"streams":{"server_to_client":["0000000178"],'
            b'"client_to_server":[]}}'
        )
        with self.assertRaisesRegex(FixtureAuditError, "duplicate"):
            self.audit(content)

    def test_rejects_invalid_hex_and_empty_chunks(self):
        base = json.loads(fixture_bytes([frame(b"x")]))
        base["streams"]["server_to_client"] = ["0xz1"]
        with self.assertRaisesRegex(FixtureAuditError, "hexadecimal"):
            self.audit(json.dumps(base).encode())

        base["streams"]["server_to_client"] = [""]
        with self.assertRaisesRegex(FixtureAuditError, "hexadecimal"):
            self.audit(json.dumps(base).encode())

    def test_requires_both_directions_and_receive_data(self):
        base = json.loads(fixture_bytes([frame(b"x")]))
        del base["streams"]["client_to_server"]
        with self.assertRaisesRegex(FixtureAuditError, "both stream directions"):
            self.audit(json.dumps(base).encode())

        empty_client = fixture_bytes([frame(b"x")], [])
        with self.assertRaisesRegex(
            FixtureAuditError, "client_to_server must contain at least one chunk"
        ):
            self.audit(empty_client)

        empty_server = fixture_bytes([], [b"\x00"])
        with self.assertRaisesRegex(
            FixtureAuditError, "server_to_client must contain at least one chunk"
        ):
            self.audit(empty_server)

    def test_resource_limits_are_validated_before_candidate_processing(self):
        content = fixture_bytes([frame(b"x")])
        with self.assertRaisesRegex(FixtureAuditError, "payload limit"):
            self.audit(content, max_payload_bytes=True)
        with self.assertRaisesRegex(FixtureAuditError, "buffer limit"):
            self.audit(content, max_buffer_bytes=3)
        with self.assertRaisesRegex(FixtureAuditError, "size limit"):
            self.audit(content, max_fixture_bytes=8)

    def test_combined_stream_budget_is_enforced_incrementally(self):
        with patch("tools.protocol_fixture_audit.MAX_TOTAL_STREAM_BYTES", 5):
            exact_budget = self.audit(fixture_bytes([frame(b"")], [b"\x01"]))
            self.assertEqual(
                exact_budget["server_to_client"]["stream_bytes"]
                + exact_budget["client_to_server"]["stream_bytes"],
                5,
            )

            over_budget = fixture_bytes([frame(b"")], [b"\x01\x02"])
            with self.assertRaisesRegex(FixtureAuditError, "combined stream data"):
                self.audit(over_budget)

    def test_decode_chunks_validates_remaining_budget_type_and_range(self):
        for invalid in (True, -1, 8 * 1024 * 1024 + 1):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                FixtureAuditError, "remaining stream byte budget"
            ):
                _decode_chunks(
                    [],
                    "client_to_server",
                    remaining_total_bytes=invalid,
                )

    def test_summary_never_emits_fixture_bytes_or_local_path(self):
        private_payload = bytes.fromhex("deadc0de11223344")
        content = fixture_bytes([frame(private_payload)])
        result = self.audit(content)
        serialized = json.dumps(result)

        self.assertNotIn(private_payload.hex(), serialized)
        self.assertNotIn(content.decode("utf-8"), serialized)
        self.assertNotIn("fixture_path", result)
        self.assertFalse(result["raw_bytes_emitted"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["authorization_independently_verified"])

    def test_private_file_reader_accepts_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-fixture.json"
            path.write_bytes(fixture_bytes([frame(b"x")]))
            result = inspect_fixture_file(str(path), expected_apk_sha256=APK_SHA256)
            self.assertEqual(result["status"], "candidate_analysis_only")

    def test_private_file_reader_rejects_symlink(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            link = root / "link.json"
            target.write_bytes(fixture_bytes([frame(b"x")]))
            try:
                link.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(FixtureAuditError, "non-symlink"):
                inspect_fixture_file(str(link), expected_apk_sha256=APK_SHA256)

    @unittest.skipUnless(
        hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
        "non-blocking FIFO support is unavailable",
    )
    def test_private_file_reader_does_not_block_on_fifo_swap_race(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-fixture.json"
            path.write_bytes(fixture_bytes([frame(b"x")]))
            real_open = os.open

            def replace_with_fifo_then_open(name, flags, *args, **kwargs):
                path.unlink()
                os.mkfifo(path)
                self.assertTrue(flags & os.O_NONBLOCK)
                return real_open(name, flags, *args, **kwargs)

            with patch(
                "tools.protocol_fixture_audit.os.open",
                side_effect=replace_with_fifo_then_open,
            ):
                with self.assertRaisesRegex(
                    FixtureAuditError, "changed before it could be read"
                ):
                    inspect_fixture_file(
                        str(path), expected_apk_sha256=APK_SHA256
                    )

    def test_cli_prints_only_redacted_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-fixture.json"
            payload = bytes.fromhex("cafebabe")
            path.write_bytes(fixture_bytes([frame(payload)]))
            output = StringIO()
            with redirect_stdout(output):
                code = main([
                    "--fixture", str(path),
                    "--apk-sha256", APK_SHA256,
                ])
            self.assertEqual(code, 0)
            self.assertNotIn(payload.hex(), output.getvalue())
            self.assertIn('"raw_bytes_emitted": false', output.getvalue())


    def test_schema_v1_reports_that_cross_direction_order_was_not_recorded(self):
        result = self.audit(fixture_bytes([frame(b"server")], [b"client"]))
        self.assertEqual(
            result["exchange_order"],
            {
                "status": "not_recorded_schema_v1",
                "event_count": None,
                "client_to_server_event_count": None,
                "server_to_client_event_count": None,
                "direction_switch_count": None,
            },
        )

    def test_schema_v2_preserves_ordered_io_ranges_without_emitting_offsets(self):
        server_stream = frame(b"server")
        private_client = b"xyz"
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 2},
            {"direction": "server_to_client", "offset": 0, "length": 3},
            {"direction": "client_to_server", "offset": 2, "length": 1},
            {
                "direction": "server_to_client",
                "offset": 3,
                "length": len(server_stream) - 3,
            },
        ]
        content = fixture_bytes(
            [server_stream[:3], server_stream[3:]],
            [private_client[:2], private_client[2:]],
            schema_version=2,
            io_events=events,
        )
        result = self.audit(content)
        self.assertEqual(result["status"], "candidate_analysis_only")
        self.assertEqual(
            result["exchange_order"],
            {
                "status": "operator_order_preserved_unverified",
                "event_count": 4,
                "client_to_server_event_count": 2,
                "server_to_client_event_count": 2,
                "direction_switch_count": 3,
            },
        )
        serialized = json.dumps(result)
        self.assertNotIn(private_client.hex(), serialized)
        self.assertNotIn('"offset"', serialized)
        self.assertNotIn('"length"', serialized)
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["authorization_independently_verified"])

    def test_schema_v2_rejects_invalid_or_incomplete_io_event_ranges(self):
        server_stream = frame(b"s")
        client_stream = b"xy"
        valid = [
            {"direction": "client_to_server", "offset": 0, "length": 2},
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream)},
        ]
        invalid_cases = (
            (
                [{"direction": "unknown", "offset": 0, "length": 2}, valid[1]],
                "invalid direction",
            ),
            (
                [{"direction": "client_to_server", "offset": True, "length": 2}, valid[1]],
                "offset must be",
            ),
            (
                [{"direction": "client_to_server", "offset": 0, "length": 0}, valid[1]],
                "length must be",
            ),
            (
                [{"direction": "client_to_server", "offset": 1, "length": 1}, valid[1]],
                "contiguously",
            ),
            (
                [valid[0], {"direction": "client_to_server", "offset": 0, "length": 1}, valid[1]],
                "contiguously",
            ),
            (
                [{"direction": "client_to_server", "offset": 0, "length": 3}, valid[1]],
                "exceeds",
            ),
            (
                [valid[0], {"direction": "server_to_client", "offset": 0, "length": 1}],
                "every byte",
            ),
            (
                [valid[0], {**valid[1], "extra": "not allowed"}],
                "invalid object",
            ),
            (
                [valid[0], "not an event"],
                "invalid object",
            ),
        )
        for events, message in invalid_cases:
            with self.subTest(events=events), self.assertRaisesRegex(
                FixtureAuditError, message
            ):
                self.audit(
                    fixture_bytes(
                        [server_stream],
                        [client_stream],
                        schema_version=2,
                        io_events=events,
                    )
                )

    def test_schema_v2_enforces_a_bounded_event_count(self):
        server_stream = frame(b"s")
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream)},
        ]
        with patch("tools.protocol_fixture_audit.MAX_IO_EVENTS", 1):
            with self.assertRaisesRegex(FixtureAuditError, "event limit"):
                self.audit(
                    fixture_bytes(
                        [server_stream],
                        [b"c"],
                        schema_version=2,
                        io_events=events,
                    )
                )

    def test_schema_v2_requires_the_timeline_field_and_rejects_unknown_fields(self):
        base = json.loads(
            fixture_bytes(
                [frame(b"s")],
                [b"c"],
                schema_version=2,
                io_events=[
                    {"direction": "client_to_server", "offset": 0, "length": 1},
                    {"direction": "server_to_client", "offset": 0, "length": len(frame(b"s"))},
                ],
            )
        )
        del base["io_events"]
        with self.assertRaisesRegex(FixtureAuditError, "object shape"):
            self.audit(json.dumps(base).encode())

        base["io_events"] = []
        base["unexpected"] = True
        with self.assertRaisesRegex(FixtureAuditError, "object shape"):
            self.audit(json.dumps(base).encode())


    def test_schema_v3_reports_relative_monotonic_timing_without_absolute_values(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 2, "elapsed_ns": 0},
            {"direction": "server_to_client", "offset": 0, "length": 3, "elapsed_ns": 0},
            {"direction": "client_to_server", "offset": 2, "length": len(client_stream) - 2, "elapsed_ns": 2_500_000},
            {"direction": "server_to_client", "offset": 3, "length": len(server_stream) - 3, "elapsed_ns": 6_000_000},
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=3,
                io_events=events,
            )
        )
        self.assertEqual(
            result["exchange_order"]["timing"],
            {
                "status": "relative_monotonic_summary_unverified",
                "event_span_ns": 6_000_000,
                "max_inter_event_gap_ns": 3_500_000,
                "absolute_timestamps_emitted": False,
            },
        )
        serialized = json.dumps(result)
        self.assertNotIn("elapsed_ns", serialized)
        self.assertNotIn('"offset"', serialized)
        self.assertNotIn('"length"', serialized)
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["authorization_independently_verified"])

    def test_schema_v3_rejects_invalid_elapsed_values_and_non_monotonic_order(self):
        server_stream = frame(b"s")
        client_stream = b"c"
        valid_prefix = {
            "direction": "client_to_server",
            "offset": 0,
            "length": 1,
            "elapsed_ns": 0,
        }
        valid_suffix = {
            "direction": "server_to_client",
            "offset": 0,
            "length": len(server_stream),
            "elapsed_ns": 1,
        }
        invalid_cases = (
            ({**valid_prefix, "elapsed_ns": True}, "elapsed_ns must be"),
            ({**valid_prefix, "elapsed_ns": -1}, "elapsed_ns must be"),
            ({**valid_prefix, "elapsed_ns": 1.5}, "elapsed_ns must be"),
            ({**valid_prefix, "elapsed_ns": MAX_CAPTURE_ELAPSED_NS + 1}, "elapsed_ns must be"),
            ({**valid_prefix, "elapsed_ns": 1}, "elapsed_ns must start at zero"),
        )
        for first, message in invalid_cases:
            with self.subTest(first=first), self.assertRaisesRegex(
                FixtureAuditError, message
            ):
                self.audit(
                    fixture_bytes(
                        [server_stream],
                        [client_stream],
                        schema_version=3,
                        io_events=[first, valid_suffix],
                    )
                )

        decreasing_client_stream = b"cc"
        decreasing = [
            valid_prefix,
            {
                "direction": "server_to_client",
                "offset": 0,
                "length": len(server_stream),
                "elapsed_ns": 10,
            },
            {
                "direction": "client_to_server",
                "offset": 1,
                "length": 1,
                "elapsed_ns": 9,
            },
        ]
        with self.assertRaisesRegex(FixtureAuditError, "monotonic"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [decreasing_client_stream],
                    schema_version=3,
                    io_events=decreasing,
                )
            )

    def test_schema_v3_requires_elapsed_field_and_rejects_unknown_event_fields(self):
        server_stream = frame(b"s")
        client_stream = b"c"
        missing_elapsed = [
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream), "elapsed_ns": 1},
        ]
        with self.assertRaisesRegex(FixtureAuditError, "invalid object"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=3,
                    io_events=missing_elapsed,
                )
            )

        extra_field = [
            {"direction": "client_to_server", "offset": 0, "length": 1, "elapsed_ns": 0, "timestamp": "private"},
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream), "elapsed_ns": 1},
        ]
        with self.assertRaisesRegex(FixtureAuditError, "invalid object"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=3,
                    io_events=extra_field,
                )
            )


if __name__ == "__main__":
    unittest.main()
