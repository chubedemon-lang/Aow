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




    def test_delegate_constructor_summary_reports_pointer_like_shape_redacted(self):
        def ldr_x(destination, base, byte_offset):
            return 0xF9400000 | ((byte_offset // 8) << 10) | (base << 5) | destination

        def mov_x(destination, source):
            return 0xAA0003E0 | (source << 16) | destination

        def str_x(source, base, byte_offset):
            return 0xF9000000 | ((byte_offset // 8) << 10) | (base << 5) | source

        code = (
            0xF81D0FFE,
            0xA90157F6,
            0xA9024FF4,
            ldr_x(8, 2, 8),
            mov_x(20, 2),
            mov_x(21, 1),
            mov_x(19, 0),
            str_x(2, 0, 0x28),
            str_x(8, 0, 0x10),
        )
        report = inspect_bytes(
            make_metadata(
                [".ctor"],
                type_name="OnMessageReceivedDelegate",
                namespace="com.geargames.common.network",
            ),
            make_elf(1, text_words=code),
        )
        summary = report["callsite_summary"][0]["delegate_constructor_argument_shape"]
        self.assertTrue(summary["argument_pointer_dereferenced"])
        self.assertTrue(summary["argument_pointer_retained_on_receiver"])
        self.assertTrue(summary["dereferenced_value_retained_on_receiver"])
        rendered = json.dumps(summary)
        self.assertNotIn("0x28", rendered)
        self.assertNotIn("0x10", rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])

if __name__ == "__main__":
    unittest.main()
