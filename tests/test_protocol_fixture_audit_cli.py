"""End-to-end CLI contract tests for schema-v4 private fixture audits."""
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from tools.protocol_fixture_audit import main


APK_SHA256 = "a" * 64


class SchemaV4FixtureAuditCliTests(unittest.TestCase):
    def test_both_offset_hypotheses_are_redacted_and_unranked(self):
        private_payload = b"private-cli-fixture-payload"
        server_payload = b"synthetic-server-payload"
        server_stream = (
            len(server_payload).to_bytes(4, "big", signed=True) + server_payload
        )
        client_stream = (
            b"ABCD"
            + len(private_payload).to_bytes(4, "big", signed=True)
            + private_payload
        )
        document = {
            "schema_version": 4,
            "apk_sha256": APK_SHA256,
            "client_unchanged": True,
            "capture_kind": "authorized_local_runtime",
            "observer_role": "client",
            "streams": {
                "server_to_client": [server_stream.hex()],
                "client_to_server": [client_stream.hex()],
            },
            "io_events": [
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
                    "elapsed_ns": 1,
                    "operation": "receive",
                },
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "private-fixture.json"
            fixture.write_text(json.dumps(document), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main([
                    "--fixture", str(fixture),
                    "--apk-sha256", APK_SHA256,
                    "--client-to-server-test-both-length-offsets",
                ])

        self.assertEqual(exit_code, 0)
        report = json.loads(output.getvalue())
        hypotheses = report["client_to_server"]["length_prefix_hypotheses"]
        self.assertEqual(
            [item["length_field_offset_from_stream_start"] for item in hypotheses],
            [0, 4],
        )
        self.assertEqual(
            report["client_to_server"]["hypothesis_comparison"],
            "independent_no_ranking",
        )
        self.assertEqual(
            [item["candidate"]["status"] for item in hypotheses],
            ["candidate_not_recovered", "candidate_frames_recovered"],
        )
        serialized = output.getvalue()
        self.assertNotIn(private_payload.hex(), serialized)
        self.assertNotIn(client_stream.hex(), serialized)
        self.assertNotIn(str(fixture), serialized)
        self.assertFalse(report["raw_bytes_emitted"])
        self.assertFalse(report["authorization_independently_verified"])
        self.assertFalse(report["sender_symmetry_verified"])
        self.assertFalse(report["wire_contract_verified"])
        self.assertFalse(report["apk_compatible"])


if __name__ == "__main__":
    unittest.main()
