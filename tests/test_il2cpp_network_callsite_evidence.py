"""Synthetic tests for the redacted native network callsite inventory."""
import json
import struct
import unittest

from test_il2cpp_native_method_evidence import make_elf, make_metadata
from tools.aarch64_call_argument_evidence import summarize_small_argument_constants
from tools.il2cpp_network_callsite_evidence import (
    CALLSITE_ARGUMENT_TARGET_PREFIXES,
    inspect_bytes,
    NETWORK_SUPPORT_METHODS,
    _metadata_method_definitions,
    _static_data_reader,
)


class NetworkCallsiteEvidenceTests(unittest.TestCase):
    def test_metadata_method_definition_labels_keep_owner_and_arity(self):
        metadata = make_metadata(
            ["MoveNext"],
            type_name="<StartConnectToServer>d__12",
            namespace="",
        )
        labels = _metadata_method_definitions(metadata)
        self.assertEqual(
            labels[0],
            ["<StartConnectToServer>d__12::MoveNext/p0"],
        )

    def test_static_data_reader_is_bounded_to_unique_allocated_non_executable_sections(self):
        token = 0x6000000B
        data = struct.pack("<Q", token)
        sections = {
            ".data": {
                "type": 1, "flags": 3, "address": 0x9000,
                "offset": 0, "size": len(data),
            },
            ".text": {
                "type": 1, "flags": 6, "address": 0xA000,
                "offset": 0, "size": len(data),
            },
        }
        read_u64 = _static_data_reader(data, sections)
        self.assertEqual(read_u64(0x9000), token)
        self.assertIsNone(read_u64(0x9001))
        self.assertIsNone(read_u64(0xA000))

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

    def test_connection_bootstrap_state_machine_is_an_explicit_callsite_root(self):
        report = inspect_bytes(
            make_metadata(
                ["MoveNext"],
                type_name="<StartConnectToServer>d__12",
                namespace="",
            ),
            make_elf(1),
        )
        self.assertEqual(report["selected_method_records"], 1)
        self.assertEqual(report["resolved_entry_windows"], 1)
        self.assertEqual(
            (report["callsite_summary"][0]["type"],
             report["callsite_summary"][0]["method"]),
            ("<StartConnectToServer>d__12", "MoveNext"),
        )

    def test_safe_register_and_delegate_constructor_are_allowlisted(self):
        dispatcher = inspect_bytes(
            make_metadata(
                ["SafeRegister"],
                type_name="MessageDispatcher",
                namespace="com.geargames.common.network",
            ),
            make_elf(1),
        )
        self.assertEqual(dispatcher["selected_method_records"], 1)
        self.assertEqual(dispatcher["resolved_entry_windows"], 1)
        self.assertIn(
            "MessageDispatcher::SafeRegister",
            CALLSITE_ARGUMENT_TARGET_PREFIXES,
        )
        self.assertIn(
            ("com.geargames.common.network", "OnMessageReceivedDelegate"),
            NETWORK_SUPPORT_METHODS,
        )

    def test_safe_register_small_arguments_are_reported_without_native_addresses(self):
        target = 0x4000
        label = (
            "com.geargames.common.network.MessageDispatcher::SafeRegister/p2"
        )

        def movz_w(register, immediate):
            return 0x52800000 | ((immediate & 0xFFFF) << 5) | register

        def bl(pc, destination):
            delta = destination - pc
            if delta % 4:
                raise ValueError("unaligned branch target")
            return 0x94000000 | ((delta // 4) & 0x03FFFFFF)

        code = b"".join(
            struct.pack("<I", word)
            for word in (
                movz_w(1, 5004),
                bl(0x1004, target),
                movz_w(1, 5005),
                bl(0x100C, target),
            )
        )
        observations = summarize_small_argument_constants(
            code,
            0x1000,
            {target: [label]},
            target_prefixes=CALLSITE_ARGUMENT_TARGET_PREFIXES,
        )
        self.assertEqual(
            [item["known_small_argument_constants"]["x1"]
             for item in observations],
            [5004, 5005],
        )
        rendered = json.dumps(observations)
        self.assertNotIn("0x4000", rendered)
        self.assertNotIn("0x1004", rendered)



if __name__ == "__main__":
    unittest.main()
