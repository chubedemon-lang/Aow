"""Exhaustive observer-role direction mapping tests for schema-v4 fixture audits.

These tests validate only the operator-asserted I/O label mapping. They do not
authenticate the observer or establish packet boundaries or wire semantics.
"""
import unittest

from tools.protocol_fixture_audit import FixtureAuditError, _validate_io_events


class ObserverDirectionMatrixTests(unittest.TestCase):
    def test_all_observer_role_operation_pairs_map_to_the_expected_stream(self):
        expected = {
            ("client", "send"): "client_to_server",
            ("client", "receive"): "server_to_client",
            ("server", "send"): "server_to_client",
            ("server", "receive"): "client_to_server",
        }
        for (role, operation), direction in expected.items():
            with self.subTest(role=role, operation=operation):
                events = [
                    {
                        "direction": direction,
                        "offset": 0,
                        "length": 1,
                        "elapsed_ns": 0,
                        "operation": operation,
                    },
                    {
                        "direction": (
                            "server_to_client"
                            if direction == "client_to_server"
                            else "client_to_server"
                        ),
                        "offset": 0,
                        "length": 1,
                        "elapsed_ns": 1,
                        "operation": (
                            "receive" if operation == "send" else "send"
                        ),
                    },
                ]
                summary = _validate_io_events(
                    events,
                    {
                        "client_to_server": 1,
                        "server_to_client": 1,
                    },
                    include_timing=True,
                    observer_role=role,
                    include_operation=True,
                )
                self.assertEqual(summary["status"], "operator_order_preserved_unverified")
                self.assertEqual(summary["observer_role_asserted"], role)
                self.assertEqual(summary["operation_semantics"], "operator_asserted_unverified")
                self.assertEqual(summary["send_event_count"], 1)
                self.assertEqual(summary["receive_event_count"], 1)

    def test_every_role_operation_pair_rejects_the_opposite_stream(self):
        expected = {
            ("client", "send"): "client_to_server",
            ("client", "receive"): "server_to_client",
            ("server", "send"): "server_to_client",
            ("server", "receive"): "client_to_server",
        }
        for (role, operation), correct_direction in expected.items():
            wrong_direction = (
                "server_to_client"
                if correct_direction == "client_to_server"
                else "client_to_server"
            )
            events = [
                {
                    "direction": wrong_direction,
                    "offset": 0,
                    "length": 1,
                    "elapsed_ns": 0,
                    "operation": operation,
                },
                {
                    "direction": correct_direction,
                    "offset": 0,
                    "length": 1,
                    "elapsed_ns": 1,
                    "operation": "receive" if operation == "send" else "send",
                },
            ]
            with self.subTest(role=role, operation=operation), self.assertRaisesRegex(
                FixtureAuditError, "does not match observer role"
            ):
                _validate_io_events(
                    events,
                    {
                        "client_to_server": 1,
                        "server_to_client": 1,
                    },
                    include_timing=True,
                    observer_role=role,
                    include_operation=True,
                )


if __name__ == "__main__":
    unittest.main()
