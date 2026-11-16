"""Tests for the private, redacted-output stream fixture inspector."""
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from tools.protocol_fixture_audit import (
    FixtureAuditError,
    audit_fixture_bytes,
    inspect_fixture_file,
    main,
)


APK_SHA256 = "a" * 64


def frame(payload):
    return len(payload).to_bytes(4, "big", signed=True) + payload


def fixture_bytes(
    server_chunks,
    client_chunks=(),
    *,
    apk_sha256=APK_SHA256,
    client_unchanged=True,
    capture_kind="authorized_local_runtime",
):
    document = {
        "schema_version": 1,
        "apk_sha256": apk_sha256,
        "client_unchanged": client_unchanged,
        "capture_kind": capture_kind,
        "streams": {
            "server_to_client": [chunk.hex() for chunk in server_chunks],
            "client_to_server": [chunk.hex() for chunk in client_chunks],
        },
    }
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

    def test_truncated_receive_candidate_is_reported_without_guessing(self):
        result = self.audit(fixture_bytes([frame(b"payload")[:-1]]))
        candidate = result["server_to_client"]["receive_candidate"]

        self.assertEqual(result["status"], "candidate_not_recovered")
        self.assertEqual(candidate["reason"], "TruncatedFrame")
        self.assertEqual(candidate["frame_count"], 0)

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

        base["streams"]["client_to_server"] = []
        base["streams"]["server_to_client"] = []
        with self.assertRaisesRegex(FixtureAuditError, "at least one chunk"):
            self.audit(json.dumps(base).encode())

    def test_resource_limits_are_validated_before_candidate_processing(self):
        content = fixture_bytes([frame(b"x")])
        with self.assertRaisesRegex(FixtureAuditError, "payload limit"):
            self.audit(content, max_payload_bytes=True)
        with self.assertRaisesRegex(FixtureAuditError, "buffer limit"):
            self.audit(content, max_buffer_bytes=3)
        with self.assertRaisesRegex(FixtureAuditError, "size limit"):
            self.audit(content, max_fixture_bytes=8)

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


if __name__ == "__main__":
    unittest.main()
