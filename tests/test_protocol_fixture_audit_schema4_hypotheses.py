"""Schema-v4 regression for independent client length hypotheses.

Synthetic fixture only; candidate alignment is not packet or wire proof.
"""
import json
import unittest

from tools.protocol_fixture_audit import audit_fixture_bytes


APK_SHA256 = "a" * 64


def _frame(payload):
    return len(payload).to_bytes(4, "big", signed=True) + payload


class SchemaV4TwoOffsetAuditTests(unittest.TestCase):
    def test_two_offset_hypotheses_preserve_v4_assertions_without_ranking(self):
        server_stream = _frame(b"server")
        private_payload = b"private-client-payload"
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

        result = audit_fixture_bytes(
            json.dumps(document, separators=(",", ":")).encode("utf-8"),
            expected_apk_sha256=APK_SHA256,
            client_to_server_test_both_length_offsets=True,
        )

        report = result["client_to_server"]
        self.assertEqual(
            report["hypothesis_comparison"], "independent_no_ranking"
        )
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
        self.assertEqual(
            result["exchange_order"]["observer_role_asserted"], "client"
        )
        self.assertEqual(
            result["exchange_order"]["operation_semantics"],
            "operator_asserted_unverified",
        )
        self.assertEqual(result["exchange_order"]["send_event_count"], 1)
        self.assertEqual(result["exchange_order"]["receive_event_count"], 1)
        self.assertEqual(
            result["client_to_server_candidate_io_alignment"]["status"],
            "not_applicable_multiple_independent_hypotheses",
        )

        serialized = json.dumps(result)
        self.assertNotIn(private_payload.hex(), serialized)
        self.assertNotIn(client_stream.hex(), serialized)
        self.assertFalse(result["raw_bytes_emitted"])
        self.assertFalse(result["authorization_independently_verified"])
        self.assertFalse(result["sender_symmetry_verified"])
        self.assertFalse(result["wire_contract_verified"])
        self.assertFalse(result["apk_compatible"])


if __name__ == "__main__":
    unittest.main()
