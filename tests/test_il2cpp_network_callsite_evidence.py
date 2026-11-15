"""Synthetic tests for the redacted native network callsite inventory."""
import hashlib
import json
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from test_il2cpp_native_method_evidence import make_elf, make_metadata
from tools.aarch64_call_argument_evidence import summarize_small_argument_constants
from tools.il2cpp_network_callsite_evidence import (
    CALLSITE_ARGUMENT_TARGET_PREFIXES,
    _metadata_usage_static_values,
    inspect_bytes,
    inspect_apk,
    _read_apk_members,
    NETWORK_SUPPORT_METHODS,
)
from tools.il2cpp_codegen_inventory import (
    ARM64_IL2CPP_MEMBER,
    METADATA_MEMBER,
    CodegenInventoryError,
    R_AARCH64_RELATIVE,
)
from tools.il2cpp_metadata_usage_evidence import encode_method_def_usage_index


class NetworkCallsiteEvidenceTests(unittest.TestCase):
    def test_metadata_usage_cells_are_read_only_and_redacted(self):
        encoded = encode_method_def_usage_index(321, 31)
        elf = bytearray(64)
        struct.pack_into("<Q", elf, 16, encoded)
        sections = {
            ".data": {
                "type": 1,
                "flags": 3,
                "address": 0x9000,
                "offset": 16,
                "size": 8,
            },
        }
        values = _metadata_usage_static_values(
            bytes(elf),
            sections,
            {0x8000: (R_AARCH64_RELATIVE, 0x9000)},
            31,
        )
        self.assertEqual(values, {0x9000: encoded})

    def test_metadata_usage_cells_with_their_own_relocation_are_ignored(self):
        encoded = encode_method_def_usage_index(321, 31)
        elf = bytearray(64)
        struct.pack_into("<Q", elf, 16, encoded)
        sections = {
            ".data": {
                "type": 1,
                "flags": 3,
                "address": 0x9000,
                "offset": 16,
                "size": 8,
            },
        }
        relocations = {
            0x8000: (R_AARCH64_RELATIVE, 0x9000),
            0x9000: (R_AARCH64_RELATIVE, 0xA000),
        }
        self.assertEqual(
            _metadata_usage_static_values(bytes(elf), sections, relocations, 31),
            {},
        )

    def test_metadata_usage_cells_ignore_other_usage_types_and_unmarked_values(self):
        values_to_reject = (
            0x40000003,
            0x60000282,
            0x0000000160000283,
        )
        for value in values_to_reject:
            with self.subTest(value=value):
                elf = bytearray(64)
                struct.pack_into("<Q", elf, 16, value)
                sections = {
                    ".data": {
                        "type": 1,
                        "flags": 3,
                        "address": 0x9000,
                        "offset": 16,
                        "size": 8,
                    },
                }
                self.assertEqual(
                    _metadata_usage_static_values(
                        bytes(elf),
                        sections,
                        {0x8000: (R_AARCH64_RELATIVE, 0x9000)},
                        31,
                    ),
                    {},
                )

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
                movz_w(1, 0x1357),
                bl(0x1004, target),
                movz_w(1, 0x2468),
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
            [0x1357, 0x2468],
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
        self.assertEqual(report["callsite_summary"][0]["entry_window_bytes"], 64)
        summary = report["callsite_summary"][0]["delegate_constructor_argument_shape"]
        self.assertTrue(summary["argument_pointer_dereferenced"])
        self.assertTrue(summary["argument_pointer_retained_on_receiver"])
        self.assertTrue(summary["dereferenced_value_retained_on_receiver"], summary)
        rendered = json.dumps(summary)
        self.assertNotIn("0x28", rendered)
        self.assertNotIn("0x10", rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])


class OfflineApkPathReadTests(unittest.TestCase):
    @staticmethod
    def write_apk(path, metadata=b"metadata-fixture", elf=b"elf-fixture"):
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(METADATA_MEMBER, metadata)
            archive.writestr(ARM64_IL2CPP_MEMBER, elf)

    def test_inspect_apk_hashes_and_parses_members_from_one_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            self.write_apk(path, b"metadata", b"elf")
            expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch(
                "tools.il2cpp_network_callsite_evidence.inspect_bytes",
                return_value={"synthetic": True},
            ) as inspect:
                self.assertEqual(inspect_apk(path), {"synthetic": True})
            inspect.assert_called_once_with(b"metadata", b"elf", expected_digest)

    def test_rejects_symlinks_and_non_regular_apk_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.apk"
            self.write_apk(target)
            link = root / "link.apk"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(CodegenInventoryError, "regular non-symlink"):
                _read_apk_members(link)
            with self.assertRaisesRegex(CodegenInventoryError, "regular non-symlink"):
                _read_apk_members(root)

    def test_rejects_empty_and_oversized_apks_before_zip_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty.apk"
            empty.write_bytes(b"")
            with self.assertRaisesRegex(CodegenInventoryError, "size"):
                _read_apk_members(empty)

            oversized = root / "oversized.apk"
            oversized.write_bytes(b"1234")
            with patch("tools.il2cpp_network_callsite_evidence.MAX_APK", 3):
                with self.assertRaisesRegex(CodegenInventoryError, "size"):
                    _read_apk_members(oversized)

    def test_rejects_path_replacement_between_lstat_and_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample.apk"
            replacement = root / "replacement.apk"
            self.write_apk(path)
            self.write_apk(replacement)
            real_open = os.open

            def replace_then_open(candidate, flags):
                if Path(candidate) == path:
                    path.unlink()
                    path.symlink_to(replacement)
                return real_open(candidate, flags)

            with patch(
                "tools.il2cpp_network_callsite_evidence.os.open",
                side_effect=replace_then_open,
            ):
                with self.assertRaises(CodegenInventoryError):
                    _read_apk_members(path)

    def test_detects_in_place_mutation_during_zip_member_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            self.write_apk(path)
            real_zip_file = zipfile.ZipFile

            class MutatingZipFile:
                def __init__(self, stream):
                    self.inner = real_zip_file(stream)

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_value, traceback):
                    result = self.inner.__exit__(exc_type, exc_value, traceback)
                    if exc_type is None:
                        with path.open("r+b") as changed:
                            changed.seek(0)
                            changed.write(b"X")
                            changed.flush()
                    return result

                def getinfo(self, name):
                    return self.inner.getinfo(name)

                def infolist(self):
                    return self.inner.infolist()

                def open(self, *args, **kwargs):
                    return self.inner.open(*args, **kwargs)

            with patch(
                "tools.il2cpp_network_callsite_evidence.zipfile.ZipFile",
                MutatingZipFile,
            ):
                with self.assertRaisesRegex(CodegenInventoryError, "changed while reading"):
                    _read_apk_members(path)


if __name__ == "__main__":
    unittest.main()
