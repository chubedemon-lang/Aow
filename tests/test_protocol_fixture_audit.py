"""Tests for the private, redacted-output stream fixture inspector."""
import hashlib
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
    MAX_JSON_TOKENS,
    MAX_CHUNKS_PER_DIRECTION,
    MAX_IO_EVENTS,
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
    observer_role="client",
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
    if schema_version in (2, 3, 4):
        document["io_events"] = io_events
    if schema_version == 4:
        document["observer_role"] = observer_role
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


    def test_rejects_excessive_json_token_count_before_object_construction(self):
        base = fixture_bytes([frame(b"x")]).decode("utf-8")
        values = ",".join("0" for _ in range(MAX_JSON_TOKENS + 1))
        content = (base[:-1] + ', "extra":[' + values + "]}").encode("utf-8")

        with patch(
            "tools.protocol_fixture_audit.json.loads",
            side_effect=AssertionError("json.loads must not run for over-budget input"),
        ):
            with self.assertRaisesRegex(FixtureAuditError, "token count"):
                self.audit(content)

    def test_json_token_scan_ignores_token_like_text_inside_strings(self):
        base = fixture_bytes([frame(b"x")]).decode("utf-8")
        token_like_text = "0," * (MAX_JSON_TOKENS + 1)
        content = (
            base[:-1] + ', "extra":' + json.dumps(token_like_text) + "}"
        ).encode("utf-8")

        with self.assertRaisesRegex(FixtureAuditError, "object shape"):
            self.audit(content)

    def test_maximum_schema_v4_event_and_chunk_counts_fit_token_budget(self):
        server_chunks = [b"\x00"] * MAX_CHUNKS_PER_DIRECTION
        client_chunks = [b"\x00"] * MAX_CHUNKS_PER_DIRECTION
        offsets = {
            "client_to_server": 0,
            "server_to_client": 0,
        }
        events = []
        for index in range(MAX_IO_EVENTS):
            direction = (
                "client_to_server" if index % 2 == 0 else "server_to_client"
            )
            operation = "send" if direction == "client_to_server" else "receive"
            events.append({
                "direction": direction,
                "offset": offsets[direction],
                "length": 1,
                "elapsed_ns": index,
                "operation": operation,
            })
            offsets[direction] += 1

        content = fixture_bytes(
            server_chunks,
            client_chunks,
            schema_version=4,
            io_events=events,
            observer_role="client",
        )
        result = self.audit(content)
        self.assertEqual(result["exchange_order"]["event_count"], MAX_IO_EVENTS)
        self.assertEqual(
            result["server_to_client"]["chunk_count"],
            MAX_CHUNKS_PER_DIRECTION,
        )
        self.assertEqual(
            result["client_to_server"]["chunk_count"],
            MAX_CHUNKS_PER_DIRECTION,
        )

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
        self.assertEqual(result["fixture_sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(result["fixture_size_bytes"], len(content))
        self.assertNotEqual(result["fixture_sha256"], APK_SHA256)
        self.assertFalse(result["raw_bytes_emitted"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["authorization_independently_verified"])

    def test_fixture_digest_identifies_exact_input_bytes_not_normalized_json(self):
        compact = fixture_bytes([frame(b"same-payload")])
        whitespace_variant = compact + b" \n"

        compact_result = self.audit(compact)
        whitespace_result = self.audit(whitespace_variant)

        self.assertEqual(
            compact_result["fixture_sha256"],
            hashlib.sha256(compact).hexdigest(),
        )
        self.assertEqual(
            whitespace_result["fixture_sha256"],
            hashlib.sha256(whitespace_variant).hexdigest(),
        )
        self.assertNotEqual(
            compact_result["fixture_sha256"],
            whitespace_result["fixture_sha256"],
        )
        self.assertEqual(
            compact_result["server_to_client"],
            whitespace_result["server_to_client"],
        )
        self.assertFalse(compact_result["wire_contract_verified"])
        self.assertFalse(whitespace_result["apk_compatible"])

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
        alignment = result["receive_candidate_io_alignment"]
        self.assertEqual(
            alignment["status"],
            "io_event_boundaries_not_recorded_schema_v1",
        )
        self.assertEqual(alignment["candidate_frame_boundary_count"], 1)
        self.assertIsNone(alignment["server_to_client_io_event_boundary_count"])
        self.assertFalse(alignment["absolute_offsets_emitted"])
        self.assertFalse(alignment["packet_boundaries_verified"])

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


    def test_client_candidate_alignment_uses_client_events_only(self):
        server_stream = frame(b"server")
        first_client_frame = frame(b"a")
        second_client_frame = frame(b"bc")
        client_stream = first_client_frame + second_client_frame
        events = [
            {"direction": "client_to_server", "offset": 0, "length": len(first_client_frame)},
            {"direction": "server_to_client", "offset": 0, "length": 4},
            {
                "direction": "client_to_server",
                "offset": len(first_client_frame),
                "length": len(second_client_frame),
            },
            {"direction": "server_to_client", "offset": 4, "length": len(server_stream) - 4},
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream[:3], client_stream[3:]],
                schema_version=2,
                io_events=events,
            ),
            client_to_server_length_offset=0,
        )
        alignment = result["client_to_server_candidate_io_alignment"]
        self.assertEqual(
            alignment["status"],
            "unverified_candidate_io_boundary_correlation",
        )
        self.assertEqual(alignment["candidate_frame_boundary_count"], 2)
        self.assertEqual(alignment["client_to_server_io_event_boundary_count"], 2)
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 2
        )
        self.assertEqual(
            alignment["candidate_frame_boundaries_not_aligned_with_io_event_ends"], 0
        )
        self.assertEqual(
            alignment["io_event_ends_aligned_with_known_candidate_frame_boundaries"], 2
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 0
        )
        self.assertTrue(alignment["candidate_boundary_set_complete"])
        self.assertFalse(alignment["absolute_offsets_emitted"])
        self.assertFalse(alignment["packet_boundaries_verified"])
        serialized = json.dumps(result)
        self.assertNotIn('"offset"', serialized)
        self.assertNotIn('"length"', serialized)
        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

    def test_client_candidate_alignment_marks_partial_tail_as_lower_bound(self):
        server_stream = frame(b"server")
        complete = frame(b"ok")
        client_stream = complete + b"\x7f"
        events = [
            {"direction": "client_to_server", "offset": 0, "length": len(complete)},
            {
                "direction": "server_to_client",
                "offset": 0,
                "length": len(server_stream),
            },
            {
                "direction": "client_to_server",
                "offset": len(complete),
                "length": 1,
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=2,
                io_events=events,
            ),
            client_to_server_length_offset=0,
        )
        candidate = result["client_to_server"]["length_prefix_candidate"]
        alignment = result["client_to_server_candidate_io_alignment"]
        self.assertEqual(candidate["status"], "candidate_not_recovered")
        self.assertEqual(candidate["frame_count"], 1)
        self.assertEqual(candidate["unclassified_stream_bytes"], 1)
        self.assertFalse(candidate["candidate_stream_fully_consumed"])
        self.assertEqual(alignment["candidate_frame_boundary_count"], 1)
        self.assertTrue(alignment["candidate_frame_boundary_count_is_lower_bound"])
        self.assertFalse(alignment["candidate_boundary_set_complete"])
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 1
        )
        self.assertFalse(alignment["packet_boundaries_verified"])
        overlap = alignment["interval_overlap"]
        self.assertEqual(overlap["io_events_without_complete_candidate_frame"], 1)
        self.assertFalse(overlap["candidate_frame_set_complete"])

    def test_client_candidate_alignment_reports_missing_events_for_schema_v1(self):
        result = self.audit(
            fixture_bytes([frame(b"server")], [frame(b"client")]),
            client_to_server_length_offset=0,
        )
        alignment = result["client_to_server_candidate_io_alignment"]
        self.assertEqual(
            alignment["status"],
            "io_event_boundaries_not_recorded_schema_v1",
        )
        self.assertEqual(alignment["candidate_frame_boundary_count"], 1)
        self.assertIsNone(alignment["client_to_server_io_event_boundary_count"])
        self.assertTrue(alignment["candidate_boundary_set_complete"])
        self.assertFalse(alignment["absolute_offsets_emitted"])
        overlap = alignment["interval_overlap"]
        self.assertEqual(overlap["status"], "io_event_boundaries_not_recorded_schema_v1")
        self.assertIsNone(overlap["frame_event_overlap_pair_count"])

    def test_client_candidate_alignment_is_not_attempted_by_default(self):
        result = self.audit(fixture_bytes([frame(b"server")], [frame(b"client")]))
        alignment = result["client_to_server_candidate_io_alignment"]
        self.assertEqual(
            alignment["status"],
            "not_attempted_sender_symmetry_unproven",
        )
        self.assertIsNone(alignment["candidate_frame_boundary_count"])
        self.assertIsNone(alignment["client_to_server_io_event_boundary_count"])
        self.assertFalse(alignment["packet_boundaries_verified"])


    def test_receive_interval_overlap_reports_one_read_containing_multiple_frames(self):
        first = frame(b"a")
        second = frame(b"bc")
        server_stream = first + second
        events = [
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream)},
            {"direction": "client_to_server", "offset": 0, "length": 1},
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [b"c"],
                schema_version=2,
                io_events=events,
            )
        )
        overlap = result["receive_candidate_io_alignment"]["interval_overlap"]
        self.assertEqual(overlap["candidate_frames_overlapping_io_events"], 2)
        self.assertEqual(overlap["candidate_frames_spanning_multiple_io_events"], 0)
        self.assertEqual(overlap["io_events_overlapping_candidate_frames"], 1)
        self.assertEqual(overlap["io_events_overlapping_multiple_candidate_frames"], 1)
        self.assertEqual(overlap["io_events_without_complete_candidate_frame"], 0)
        self.assertEqual(overlap["candidate_frames_without_io_event"], 0)
        self.assertEqual(overlap["frame_event_overlap_pair_count"], 2)
        self.assertFalse(overlap["packet_boundaries_verified"])

    def test_receive_interval_overlap_reports_one_frame_spanning_multiple_reads(self):
        server_stream = frame(b"split")
        split = len(server_stream) // 2
        events = [
            {"direction": "server_to_client", "offset": 0, "length": split},
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {
                "direction": "server_to_client",
                "offset": split,
                "length": len(server_stream) - split,
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [b"c"],
                schema_version=2,
                io_events=events,
            )
        )
        overlap = result["receive_candidate_io_alignment"]["interval_overlap"]
        self.assertEqual(overlap["candidate_frames_spanning_multiple_io_events"], 1)
        self.assertEqual(overlap["io_events_overlapping_candidate_frames"], 2)
        self.assertEqual(overlap["io_events_overlapping_multiple_candidate_frames"], 0)
        self.assertEqual(overlap["frame_event_overlap_pair_count"], 2)

    def test_client_interval_overlap_reports_split_and_coalesced_writes(self):
        first = frame(b"a")
        second = frame(b"bc")
        client_stream = first + second
        server_stream = frame(b"s")
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 2},
            {
                "direction": "server_to_client",
                "offset": 0,
                "length": len(server_stream),
            },
            {
                "direction": "client_to_server",
                "offset": 2,
                "length": len(client_stream) - 2,
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=2,
                io_events=events,
            ),
            client_to_server_length_offset=0,
        )
        overlap = result["client_to_server_candidate_io_alignment"]["interval_overlap"]
        self.assertEqual(overlap["candidate_frames_overlapping_io_events"], 2)
        self.assertEqual(overlap["candidate_frames_spanning_multiple_io_events"], 1)
        self.assertEqual(overlap["io_events_overlapping_candidate_frames"], 2)
        self.assertEqual(overlap["io_events_overlapping_multiple_candidate_frames"], 1)
        self.assertEqual(overlap["io_events_without_complete_candidate_frame"], 0)
        self.assertEqual(overlap["frame_event_overlap_pair_count"], 3)
        self.assertFalse(overlap["packet_boundaries_verified"])
        serialized = json.dumps(result)
        self.assertNotIn('"offset"', serialized)
        self.assertNotIn('"length"', serialized)
        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

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
                "per_direction": {
                    "client_to_server": {
                        "event_count": 2,
                        "event_span_ns": 2_500_000,
                        "max_inter_event_gap_ns": 2_500_000,
                    },
                    "server_to_client": {
                        "event_count": 2,
                        "event_span_ns": 6_000_000,
                        "max_inter_event_gap_ns": 6_000_000,
                    },
                },
                "absolute_timestamps_emitted": False,
            },
        )
        alignment = result["receive_candidate_io_alignment"]
        self.assertEqual(alignment["candidate_frame_boundary_count"], 1)
        self.assertEqual(alignment["server_to_client_io_event_boundary_count"], 2)
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 1
        )
        self.assertTrue(alignment["candidate_boundary_set_complete"])
        serialized = json.dumps(result)
        self.assertNotIn("elapsed_ns", serialized)
        self.assertNotIn('"offset"', serialized)
        self.assertNotIn('"length"', serialized)
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["authorization_independently_verified"])

    def test_schema_v3_reports_directional_timing_only_as_relative_durations(self):
        server_stream = frame(b"server")
        client_stream = b"client-data"
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 2, "elapsed_ns": 0},
            {"direction": "server_to_client", "offset": 0, "length": 3, "elapsed_ns": 1},
            {"direction": "client_to_server", "offset": 2, "length": 3, "elapsed_ns": 4},
            {
                "direction": "server_to_client",
                "offset": 3,
                "length": len(server_stream) - 3,
                "elapsed_ns": 7,
            },
            {
                "direction": "client_to_server",
                "offset": 5,
                "length": len(client_stream) - 5,
                "elapsed_ns": 9,
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=3,
                io_events=events,
            )
        )
        timing = result["exchange_order"]["timing"]
        self.assertEqual(
            timing["per_direction"],
            {
                "client_to_server": {
                    "event_count": 3,
                    "event_span_ns": 9,
                    "max_inter_event_gap_ns": 5,
                },
                "server_to_client": {
                    "event_count": 2,
                    "event_span_ns": 6,
                    "max_inter_event_gap_ns": 6,
                },
            },
        )
        serialized = json.dumps(result)
        self.assertNotIn("elapsed_ns", serialized)
        self.assertNotIn('"offset"', serialized)
        self.assertNotIn('"length"', serialized)
        self.assertFalse(timing["absolute_timestamps_emitted"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

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


    def test_schema_v2_correlates_candidate_frame_ends_with_io_event_ends(self):
        first = frame(b"A")
        second = frame(b"BC")
        server_stream = first + second
        client_stream = b"c"
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {"direction": "server_to_client", "offset": 0, "length": len(first)},
            {
                "direction": "server_to_client",
                "offset": len(first),
                "length": len(second),
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=2,
                io_events=events,
            )
        )
        alignment = result["receive_candidate_io_alignment"]
        self.assertEqual(
            alignment["status"],
            "unverified_candidate_io_boundary_correlation",
        )
        self.assertEqual(alignment["candidate_frame_boundary_count"], 2)
        self.assertEqual(alignment["server_to_client_io_event_boundary_count"], 2)
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 2
        )
        self.assertEqual(
            alignment["candidate_frame_boundaries_not_aligned_with_io_event_ends"], 0
        )
        self.assertEqual(
            alignment["io_event_ends_aligned_with_known_candidate_frame_boundaries"], 2
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 0
        )
        self.assertTrue(alignment["candidate_boundary_set_complete"])
        serialized = json.dumps(result)
        self.assertNotIn("_frame_end_offsets", serialized)
        self.assertFalse(alignment["absolute_offsets_emitted"])
        self.assertFalse(alignment["packet_boundaries_verified"])

    def test_schema_v2_reports_one_read_containing_multiple_candidate_frames(self):
        first = frame(b"A")
        second = frame(b"B")
        server_stream = first + second
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {
                "direction": "server_to_client",
                "offset": 0,
                "length": len(server_stream),
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [b"c"],
                schema_version=2,
                io_events=events,
            )
        )
        alignment = result["receive_candidate_io_alignment"]
        self.assertEqual(alignment["candidate_frame_boundary_count"], 2)
        self.assertEqual(alignment["server_to_client_io_event_boundary_count"], 1)
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["candidate_frame_boundaries_not_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_aligned_with_known_candidate_frame_boundaries"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 0
        )

    def test_schema_v2_reports_io_event_boundary_inside_candidate_frame(self):
        server_stream = frame(b"payload")
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {"direction": "server_to_client", "offset": 0, "length": 4},
            {
                "direction": "server_to_client",
                "offset": 4,
                "length": len(server_stream) - 4,
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [b"c"],
                schema_version=2,
                io_events=events,
            )
        )
        alignment = result["receive_candidate_io_alignment"]
        self.assertEqual(alignment["candidate_frame_boundary_count"], 1)
        self.assertEqual(alignment["server_to_client_io_event_boundary_count"], 2)
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_aligned_with_known_candidate_frame_boundaries"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 1
        )

    def test_partial_candidate_parse_marks_boundary_counts_as_lower_bound(self):
        complete = frame(b"ok")
        tail = b"HTTP"
        server_stream = complete + tail
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 1},
            {"direction": "server_to_client", "offset": 0, "length": len(complete)},
            {
                "direction": "server_to_client",
                "offset": len(complete),
                "length": len(tail),
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [b"c"],
                schema_version=2,
                io_events=events,
            )
        )
        alignment = result["receive_candidate_io_alignment"]
        self.assertEqual(alignment["candidate_frame_boundary_count"], 1)
        self.assertTrue(alignment["candidate_frame_boundary_count_is_lower_bound"])
        self.assertFalse(alignment["candidate_boundary_set_complete"])
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["io_event_ends_without_known_candidate_frame_boundary"], 1
        )



    def test_client_to_server_candidate_is_opt_in_and_does_not_claim_symmetry(self):
        client_stream = frame(b"client")
        default_result = self.audit(
            fixture_bytes([frame(b"server")], [client_stream])
        )
        self.assertEqual(
            default_result["client_to_server"]["analysis"],
            "not_attempted_sender_symmetry_unproven",
        )
        self.assertNotIn(
            "length_prefix_candidate", default_result["client_to_server"]
        )

        result = self.audit(
            fixture_bytes([frame(b"server")], [client_stream[:3], client_stream[3:]]),
            client_to_server_length_offset=0,
        )
        candidate = result["client_to_server"]["length_prefix_candidate"]
        self.assertEqual(
            result["client_to_server"]["analysis"],
            "operator_selected_generic_signed_be32_length_hypothesis_only",
        )
        self.assertEqual(candidate["length_field_offset_from_stream_start"], 0)
        self.assertTrue(candidate["candidate_stream_fully_consumed"])
        self.assertEqual(candidate["frame_sizes"], [len(client_stream)])
        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

    def test_client_to_server_candidate_can_test_an_opaque_four_byte_prefix(self):
        payload = b"outbound"
        client_stream = b"ABCD" + len(payload).to_bytes(4, "big", signed=True) + payload
        result = self.audit(
            fixture_bytes([frame(b"server")], [client_stream[:5], client_stream[5:]]),
            client_to_server_length_offset=4,
        )
        candidate = result["client_to_server"]["length_prefix_candidate"]
        self.assertEqual(candidate["length_field_offset_from_stream_start"], 4)
        self.assertTrue(candidate["bytes_before_length_field_are_opaque"])
        self.assertEqual(candidate["frame_sizes"], [len(client_stream)])
        self.assertEqual(candidate["unclassified_stream_bytes"], 0)
        self.assertFalse(result["sender_symmetry_verified"])

    def test_client_to_server_candidate_reports_negative_length_without_guessing(self):
        client_stream = bytes.fromhex("ffffffff")
        result = self.audit(
            fixture_bytes([frame(b"server")], [client_stream]),
            client_to_server_length_offset=0,
        )
        candidate = result["client_to_server"]["length_prefix_candidate"]
        self.assertEqual(candidate["status"], "candidate_not_recovered")
        self.assertEqual(candidate["reason"], "InvalidCandidateLength")
        self.assertEqual(candidate["candidate_bytes_consumed"], 0)
        self.assertEqual(candidate["unclassified_stream_bytes"], 4)
        self.assertFalse(candidate["candidate_stream_fully_consumed"])
        self.assertFalse(result["wire_contract_verified"])

    def test_client_to_server_candidate_rejects_invalid_offset_and_small_buffer(self):
        for offset in (True, False, 1, -1, 8, "0"):
            with self.subTest(offset=offset), self.assertRaisesRegex(
                FixtureAuditError, "exactly 0 or 4"
            ):
                self.audit(
                    fixture_bytes([frame(b"server")], [frame(b"client")]),
                    client_to_server_length_offset=offset,
                )
        with self.assertRaisesRegex(FixtureAuditError, "buffer limit"):
            self.audit(
                fixture_bytes([frame(b"server")], [b"ABCD" + bytes.fromhex("00000000")]),
                max_payload_bytes=0,
                max_buffer_bytes=7,
                client_to_server_length_offset=4,
            )

    def test_client_to_server_candidate_report_never_emits_private_payload(self):
        payload = bytes.fromhex("d15ea5ed11223344")
        client_stream = frame(payload)
        result = self.audit(
            fixture_bytes([frame(b"server")], [client_stream]),
            client_to_server_length_offset=0,
        )
        serialized = json.dumps(result)
        self.assertNotIn(payload.hex(), serialized)
        self.assertNotIn(client_stream.hex(), serialized)
        self.assertFalse(result["raw_bytes_emitted"])
        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

    def test_cli_opt_in_client_candidate_prints_redacted_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-fixture.json"
            payload = bytes.fromhex("cafef00d")
            path.write_bytes(
                fixture_bytes([frame(b"server")], [frame(payload)])
            )
            output = StringIO()
            with redirect_stdout(output):
                code = main([
                    "--fixture", str(path),
                    "--apk-sha256", APK_SHA256,
                    "--client-to-server-length-offset", "0",
                ])
            self.assertEqual(code, 0)
            self.assertNotIn(payload.hex(), output.getvalue())
            self.assertIn(
                "operator_selected_generic_signed_be32_length_hypothesis_only",
                output.getvalue(),
            )
            self.assertIn('"sender_symmetry_verified": false', output.getvalue())

    def test_client_to_server_both_offsets_are_reported_independently_without_ranking(self):
        payload = b"outbound"
        client_stream = (
            b"ABCD"
            + len(payload).to_bytes(4, "big", signed=True)
            + payload
        )
        result = self.audit(
            fixture_bytes([frame(b"server")], [client_stream]),
            client_to_server_test_both_length_offsets=True,
        )
        report = result["client_to_server"]
        self.assertEqual(
            report["analysis"],
            "operator_selected_generic_signed_be32_length_hypotheses_only",
        )
        self.assertEqual(report["hypothesis_comparison"], "independent_no_ranking")
        hypotheses = report["length_prefix_hypotheses"]
        self.assertEqual(
            [item["length_field_offset_from_stream_start"] for item in hypotheses],
            [0, 4],
        )
        self.assertEqual(
            hypotheses[0]["candidate"]["status"], "candidate_not_recovered"
        )
        self.assertEqual(
            hypotheses[1]["candidate"]["status"], "candidate_frames_recovered"
        )
        self.assertTrue(
            hypotheses[1]["candidate"]["candidate_stream_fully_consumed"]
        )
        self.assertTrue(hypotheses[1]["bytes_before_length_field_are_opaque"])
        self.assertEqual(
            result["client_to_server_candidate_io_alignment"]["status"],
            "not_applicable_multiple_independent_hypotheses",
        )
        serialized = json.dumps(result)
        self.assertNotIn(payload.hex(), serialized)
        self.assertNotIn(client_stream.hex(), serialized)
        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

    def test_client_to_server_both_offset_mode_rejects_conflicting_options(self):
        options = (
            {"client_to_server_length_offset": 0,
             "client_to_server_test_both_length_offsets": True},
            {"client_to_server_test_both_length_offsets": 1},
            {"client_to_server_test_both_length_offsets": None},
        )
        for kwargs in options:
            with self.subTest(kwargs=kwargs), self.assertRaises(FixtureAuditError):
                self.audit(fixture_bytes([frame(b"server")], [b"client"]), **kwargs)

    def test_cli_both_offset_mode_prints_only_redacted_independent_summaries(self):
        payload = b"private-client-fixture"
        client_stream = (
            b"ABCD"
            + len(payload).to_bytes(4, "big", signed=True)
            + payload
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-fixture.json"
            path.write_bytes(
                fixture_bytes([frame(b"server")], [client_stream])
            )
            output = StringIO()
            with redirect_stdout(output):
                code = main([
                    "--fixture", str(path),
                    "--apk-sha256", APK_SHA256,
                    "--client-to-server-test-both-length-offsets",
                ])
        self.assertEqual(code, 0)
        serialized = output.getvalue()
        self.assertNotIn(payload.hex(), serialized)
        self.assertNotIn(client_stream.hex(), serialized)
        self.assertIn('"hypothesis_comparison": "independent_no_ranking"', serialized)
        self.assertIn('"apk_compatible": false', serialized)


    def test_schema_v4_client_operations_match_stream_directions_and_are_redacted(self):
        server_stream = frame(b"server")
        client_stream = b"client-data"
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 2, "elapsed_ns": 0, "operation": "send"},
            {"direction": "server_to_client", "offset": 0, "length": 3, "elapsed_ns": 1, "operation": "receive"},
            {"direction": "client_to_server", "offset": 2, "length": len(client_stream) - 2, "elapsed_ns": 4, "operation": "send"},
            {"direction": "server_to_client", "offset": 3, "length": len(server_stream) - 3, "elapsed_ns": 7, "operation": "receive"},
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=4,
                io_events=events,
                observer_role="client",
            )
        )
        order = result["exchange_order"]
        self.assertEqual(order["observer_role_asserted"], "client")
        self.assertEqual(order["operation_semantics"], "operator_asserted_unverified")
        self.assertEqual(order["send_event_count"], 2)
        self.assertEqual(order["receive_event_count"], 2)
        self.assertEqual(order["timing"]["event_span_ns"], 7)
        serialized = json.dumps(result)
        for private_field in ('"operation"', '"observer_role"', '"elapsed_ns"', '"offset"', '"length"'):
            self.assertNotIn(private_field, serialized)
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(result["authorization_independently_verified"])

    def test_schema_v4_server_role_reverses_send_receive_direction_mapping(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        events = [
            {"direction": "server_to_client", "offset": 0, "length": 2, "elapsed_ns": 0, "operation": "send"},
            {"direction": "client_to_server", "offset": 0, "length": 2, "elapsed_ns": 3, "operation": "receive"},
            {"direction": "server_to_client", "offset": 2, "length": len(server_stream) - 2, "elapsed_ns": 5, "operation": "send"},
            {"direction": "client_to_server", "offset": 2, "length": len(client_stream) - 2, "elapsed_ns": 8, "operation": "receive"},
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=4,
                io_events=events,
                observer_role="server",
            )
        )
        order = result["exchange_order"]
        self.assertEqual(order["observer_role_asserted"], "server")
        self.assertEqual(order["send_event_count"], 2)
        self.assertEqual(order["receive_event_count"], 2)
        self.assertEqual(order["timing"]["event_span_ns"], 8)

    def test_schema_v4_rejects_operation_direction_mismatch(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        events = [
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream), "elapsed_ns": 0, "operation": "send"},
            {"direction": "client_to_server", "offset": 0, "length": len(client_stream), "elapsed_ns": 1, "operation": "receive"},
        ]
        with self.assertRaisesRegex(FixtureAuditError, "does not match observer role"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=4,
                    io_events=events,
                    observer_role="client",
                )
            )

    def test_schema_v4_rejects_invalid_observer_role_and_operation(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        valid_events = [
            {"direction": "client_to_server", "offset": 0, "length": len(client_stream), "elapsed_ns": 0, "operation": "send"},
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream), "elapsed_ns": 1, "operation": "receive"},
        ]
        for role in (None, True, "Client", "peer"):
            with self.subTest(role=role), self.assertRaisesRegex(FixtureAuditError, "observer_role"):
                self.audit(
                    fixture_bytes(
                        [server_stream],
                        [client_stream],
                        schema_version=4,
                        io_events=valid_events,
                        observer_role=role,
                    )
                )
        invalid_operation = [dict(valid_events[0], operation="write"), valid_events[1]]
        with self.assertRaisesRegex(FixtureAuditError, "operation must be exactly"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=4,
                    io_events=invalid_operation,
                    observer_role="client",
                )
            )

    def test_schema_v4_rejects_missing_or_unknown_event_fields(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        missing_operation = [
            {"direction": "client_to_server", "offset": 0, "length": len(client_stream), "elapsed_ns": 0},
            {"direction": "server_to_client", "offset": 0, "length": len(server_stream), "elapsed_ns": 1, "operation": "receive"},
        ]
        with self.assertRaisesRegex(FixtureAuditError, "invalid object"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=4,
                    io_events=missing_operation,
                )
            )
        extra_field = [
            dict(missing_operation[0], operation="send", timestamp="private"),
            missing_operation[1],
        ]
        with self.assertRaisesRegex(FixtureAuditError, "invalid object"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=4,
                    io_events=extra_field,
                )
            )


    def test_schema_v4_correlates_both_direction_candidates_without_verifying_packets(self):
        server_stream = frame(b"server")
        client_stream = frame(b"client")
        events = [
            {"direction": "client_to_server", "offset": 0, "length": 2, "elapsed_ns": 0, "operation": "send"},
            {"direction": "server_to_client", "offset": 0, "length": 3, "elapsed_ns": 1, "operation": "receive"},
            {"direction": "client_to_server", "offset": 2, "length": len(client_stream) - 2, "elapsed_ns": 4, "operation": "send"},
            {"direction": "server_to_client", "offset": 3, "length": len(server_stream) - 3, "elapsed_ns": 7, "operation": "receive"},
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=4,
                io_events=events,
                observer_role="client",
            ),
            client_to_server_length_offset=0,
        )

        receive = result["receive_candidate_io_alignment"]
        self.assertEqual(receive["status"], "unverified_candidate_io_boundary_correlation")
        self.assertEqual(receive["candidate_frame_boundary_count"], 1)
        self.assertEqual(receive["server_to_client_io_event_boundary_count"], 2)
        self.assertEqual(receive["candidate_frame_boundaries_aligned_with_io_event_ends"], 1)
        self.assertEqual(
            receive["interval_overlap"]["candidate_frames_spanning_multiple_io_events"],
            1,
        )
        self.assertEqual(
            receive["interval_overlap"]["frame_event_overlap_pair_count"],
            2,
        )

        client = result["client_to_server_candidate_io_alignment"]
        self.assertEqual(client["status"], "unverified_candidate_io_boundary_correlation")
        self.assertEqual(client["candidate_frame_boundary_count"], 1)
        self.assertEqual(client["client_to_server_io_event_boundary_count"], 2)
        self.assertEqual(client["candidate_frame_boundaries_aligned_with_io_event_ends"], 1)
        self.assertEqual(
            client["interval_overlap"]["candidate_frames_spanning_multiple_io_events"],
            1,
        )
        self.assertEqual(
            client["interval_overlap"]["frame_event_overlap_pair_count"],
            2,
        )

        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])
        self.assertFalse(receive["packet_boundaries_verified"])
        self.assertFalse(client["packet_boundaries_verified"])


    def test_schema_v4_rejects_server_observer_direction_mismatch(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        # For a server observer, server_to_client must be send and
        # client_to_server must be receive. Reverse one operation deliberately.
        events = [
            {
                "direction": "server_to_client",
                "offset": 0,
                "length": len(server_stream),
                "elapsed_ns": 0,
                "operation": "receive",
            },
            {
                "direction": "client_to_server",
                "offset": 0,
                "length": len(client_stream),
                "elapsed_ns": 1,
                "operation": "send",
            },
        ]
        with self.assertRaisesRegex(
            FixtureAuditError, "does not match observer role"
        ):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=4,
                    io_events=events,
                    observer_role="server",
                )
            )


    def test_schema_v4_inherits_relative_timing_upper_bound(self):
        server_stream = frame(b"server")
        client_stream = b"client"
        valid_events = [
            {
                "direction": "client_to_server",
                "offset": 0,
                "length": len(client_stream),
                "elapsed_ns": 0,
                "operation": "send",
            },
            {
                "direction": "server_to_client",
                "offset": 0,
                "length": len(server_stream),
                "elapsed_ns": MAX_CAPTURE_ELAPSED_NS,
                "operation": "receive",
            },
        ]
        result = self.audit(
            fixture_bytes(
                [server_stream],
                [client_stream],
                schema_version=4,
                io_events=valid_events,
                observer_role="client",
            )
        )
        self.assertEqual(
            result["exchange_order"]["timing"]["event_span_ns"],
            MAX_CAPTURE_ELAPSED_NS,
        )
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])

        over_limit_events = [
            valid_events[0],
            dict(valid_events[1], elapsed_ns=MAX_CAPTURE_ELAPSED_NS + 1),
        ]
        with self.assertRaisesRegex(FixtureAuditError, "elapsed_ns must be"):
            self.audit(
                fixture_bytes(
                    [server_stream],
                    [client_stream],
                    schema_version=4,
                    io_events=over_limit_events,
                    observer_role="client",
                )
            )


    def test_server_io_observation_boundaries_are_not_assumed_to_be_frame_boundaries(self):
        first = frame(b"A")
        second = frame(b"BC")
        server_stream = first + second
        client_stream = b"\\x10\\x20"
        document = {
            "schema_version": 4,
            "apk_sha256": APK_SHA256,
            "client_unchanged": True,
            "capture_kind": "authorized_local_runtime",
            "observer_role": "server",
            "streams": {
                "server_to_client": [server_stream.hex()],
                "client_to_server": [client_stream.hex()],
            },
            "io_events": [
                {
                    "direction": "server_to_client",
                    "offset": 0,
                    "length": 2,
                    "elapsed_ns": 0,
                    "operation": "send",
                },
                {
                    "direction": "client_to_server",
                    "offset": 0,
                    "length": 1,
                    "elapsed_ns": 1,
                    "operation": "receive",
                },
                {
                    "direction": "server_to_client",
                    "offset": 2,
                    "length": len(server_stream) - 2,
                    "elapsed_ns": 2,
                    "operation": "send",
                },
                {
                    "direction": "client_to_server",
                    "offset": 1,
                    "length": 1,
                    "elapsed_ns": 3,
                    "operation": "receive",
                },
            ],
        }

        result = self.audit(
            json.dumps(document, separators=(",", ":")).encode("utf-8")
        )
        alignment = result["server_to_client_candidate_io_alignment"]
        self.assertEqual(
            alignment["status"], "unverified_candidate_io_boundary_correlation"
        )
        self.assertEqual(alignment["candidate_frame_boundary_count"], 2)
        self.assertEqual(alignment["server_to_client_io_event_boundary_count"], 2)
        self.assertEqual(
            alignment["candidate_frame_boundaries_aligned_with_io_event_ends"], 1
        )
        self.assertEqual(
            alignment["candidate_frame_boundaries_not_aligned_with_io_event_ends"], 1
        )
        self.assertFalse(alignment["absolute_offsets_emitted"])
        self.assertFalse(alignment["packet_boundaries_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])


if __name__ == "__main__":
    unittest.main()
