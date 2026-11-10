"""Synthetic tests for the redacted native network callsite inventory."""
import json
import unittest

from test_il2cpp_native_method_evidence import make_elf, make_metadata
from tools.il2cpp_network_callsite_evidence import (
    inspect_bytes,
    NETWORK_SUPPORT_METHODS,
)


class NetworkCallsiteEvidenceTests(unittest.TestCase):
    def test_known_network_method_gets_a_redacted_callsite_record(self):
        report = inspect_bytes(
            make_metadata(["Cycle"], type_name="Receiver"),
            make_elf(1),
        )
        self.assertEqual(report["selected_method_records"], 1)
        self.assertEqual(report["resolved_entry_windows"], 1)
        self.assertEqual(report["unresolved_method_records"], 0)
        self.assertEqual(len(report["callsite_summary"]), 1)
        item = report["callsite_summary"][0]
        self.assertEqual((item["type"], item["method"]), ("Receiver", "Cycle"))
        self.assertEqual(item["entry_window_kind"],
                         "next_distinct_executable_entry_in_section")

    def test_network_buffer_support_allowlist_is_explicit(self):
        report = inspect_bytes(
            make_metadata(
                ["SetDataAvailable"],
                type_name="ClientNetworkStreamBuffer",
                namespace="com.geargames.common.utils",
            ),
            make_elf(1),
        )
        self.assertIn(
            ("com.geargames.common.utils", "ClientNetworkStreamBuffer"),
            NETWORK_SUPPORT_METHODS,
        )
        self.assertEqual(report["selected_method_records"], 1)
        self.assertEqual(report["resolved_entry_windows"], 1)
        self.assertEqual(
            (report["callsite_summary"][0]["type"],
             report["callsite_summary"][0]["method"]),
            ("ClientNetworkStreamBuffer", "SetDataAvailable"),
        )

    def test_unallowlisted_buffer_method_is_not_reported(self):
        report = inspect_bytes(
            make_metadata(
                ["Unrelated"],
                type_name="ClientNetworkStreamBuffer",
                namespace="com.geargames.common.utils",
            ),
            make_elf(1),
        )
        self.assertEqual(report["selected_method_records"], 0)
        self.assertEqual(report["callsite_summary"], [])

    def test_unrelocated_method_is_counted_but_not_given_a_window(self):
        report = inspect_bytes(
            make_metadata(
                ["SetDataAvailable"],
                type_name="ClientNetworkStreamBuffer",
                namespace="com.geargames.common.utils",
            ),
            make_elf(1, unrelocated={0}),
        )
        self.assertEqual(report["selected_method_records"], 1)
        self.assertEqual(report["resolved_entry_windows"], 0)
        self.assertEqual(report["unresolved_method_records"], 1)
        self.assertEqual(report["callsite_summary"], [])

    def test_report_never_emits_native_addresses_or_instructions(self):
        report = inspect_bytes(
            make_metadata(["Cycle"], type_name="Receiver"),
            make_elf(1),
        )
        rendered = json.dumps(report)
        for value in ("0x3000", "0x5000", "0x6000"):
            self.assertNotIn(value, rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])
        self.assertFalse(report["packet_bytes_emitted"])

    def test_serializer_classes_are_not_duplicated_as_transport_callsite_roots(self):
        report = inspect_bytes(
            make_metadata(
                ["serialize"],
                image="ConvertedAssembly.dll",
                type_name="LoginRequestSTSerializer",
                namespace="com.geargames.serialization.serializers",
            ),
            make_elf(1, image="ConvertedAssembly.dll"),
        )
        self.assertEqual(report["selected_method_records"], 0)
        self.assertEqual(report["callsite_summary"], [])


if __name__ == "__main__":
    unittest.main()
