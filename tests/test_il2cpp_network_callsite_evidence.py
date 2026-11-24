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
    _summarize_login_request_path_comparison,
    _correlate_field_info_arguments_with_control_flow_paths,
    _metadata_usage_static_values,
    _metadata_usage_static_field_info_values,
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
from tools.il2cpp_metadata_usage_evidence import (
    encode_field_info_usage_index,
    encode_method_def_usage_index,
)


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

    def test_field_info_usage_cells_are_read_only_and_redacted(self):
        encoded = encode_field_info_usage_index(321, 31)
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
        values = _metadata_usage_static_field_info_values(
            bytes(elf),
            sections,
            {0x8000: (R_AARCH64_RELATIVE, 0x9000)},
            31,
        )
        self.assertEqual(values, {0x9000: encoded})

    def test_field_info_usage_cells_ignore_other_and_unresolved_usage_tokens(self):
        values_to_reject = (
            encode_method_def_usage_index(321, 31),
            0x80000282,  # FieldInfo usage type with the v27+ unresolved marker.
            0x0000000180000283,  # More than one 32-bit token.
        )
        sections = {
            ".data": {
                "type": 1,
                "flags": 3,
                "address": 0x9000,
                "offset": 16,
                "size": 8,
            },
        }
        for value in values_to_reject:
            with self.subTest(value=value):
                elf = bytearray(64)
                struct.pack_into("<Q", elf, 16, value)
                self.assertEqual(
                    _metadata_usage_static_field_info_values(
                        bytes(elf),
                        sections,
                        {0x8000: (R_AARCH64_RELATIVE, 0x9000)},
                        31,
                    ),
                    {},
                )

    def test_field_info_usage_cells_with_their_own_relocation_are_ignored(self):
        encoded = encode_field_info_usage_index(321, 31)
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
            _metadata_usage_static_field_info_values(
                bytes(elf), sections, relocations, 31
            ),
            {},
        )

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
        provenance = item["cfg_memory_base_provenance_observations"]
        self.assertEqual(
            provenance["analysis_kind"], "bounded_cfg_memory_base_provenance"
        )
        self.assertFalse(provenance["absolute_addresses_emitted"])
        self.assertFalse(provenance["raw_instructions_emitted"])
        return_tests = item["immediate_call_result_zero_tests"]
        self.assertEqual(return_tests["analysis_kind"], "immediate_call_result_zero_test_candidate")
        self.assertFalse(return_tests["native_addresses_emitted"])
        self.assertFalse(return_tests["raw_instructions_emitted"])


    def test_network_method_memory_access_is_cross_referenced_to_fieldinfo_cell(self):
        metadata = bytearray(make_metadata(
            ["Cycle"],
            fields=[("probeField", 0, 0x04000001)],
        ))
        metadata.extend(bytes((-len(metadata)) % 8))
        field_ref_offset = len(metadata)
        metadata.extend(struct.pack("<ii", 0, 0))
        struct.pack_into("<II", metadata, 0xB8, field_ref_offset, 8)

        encoded = encode_field_info_usage_index(0, 31)
        pc = 0x5000
        target_page = 0x3000
        page_delta = (target_page - (pc & ~0xFFF)) >> 12
        immediate = page_delta & ((1 << 21) - 1)
        adrp_x8 = (
            0x90000000
            | ((immediate & 0x3) << 29)
            | (((immediate >> 2) & 0x7FFFF) << 5)
            | 8
        )
        add_x8_x8_0x70 = 0x91000000 | (0x70 << 10) | (8 << 5) | 8
        ldr_x9_x8 = 0xF9400000 | (8 << 5) | 9
        elf = make_elf(
            1,
            text_words=(
                adrp_x8,
                add_x8_x8_0x70,
                ldr_x9_x8,
                0xF9400000 | (9 << 5) | 10,  # LDR X10, [X9]
            ),
            include_native_type_table=True,
            field_info_token=encoded,
        )
        report = inspect_bytes(
            bytes(metadata), elf, resolve_fieldref_native_types=True
        )
        receiver = next(
            item for item in report["callsite_summary"]
            if item["method"] == "Cycle"
        )
        provenance = receiver["cfg_memory_base_provenance_observations"]
        self.assertEqual(provenance["known_static_cell_match_count"], 1)
        self.assertEqual(provenance["known_static_cell_load_match_count"], 1)
        self.assertEqual(provenance["known_static_cell_store_match_count"], 0)
        self.assertEqual(
            provenance["known_static_cell_full_width_load_match_count"], 1
        )
        self.assertEqual(
            provenance["known_static_cell_derived_base_access_count"], 1
        )
        self.assertTrue(provenance["memory_accesses"][0]["matches_known_static_cell"])
        self.assertTrue(
            provenance["memory_accesses"][1]["base_derived_from_known_static_cell"]
        )
        self.assertEqual(
            report["field_info_usage_correlation"]["references"][0]["native_type"]["type_name"],
            "I4",
        )
        rendered = json.dumps(report)
        self.assertNotIn("0x3070", rendered)
        self.assertFalse(report["native_addresses_emitted"])

    def test_inspect_bytes_correlates_static_field_info_tokens_to_field_refs(self):
        metadata = bytearray(make_metadata(
            ["Cycle"],
            fields=[("probeField", 17, 0x04000001)],
        ))
        metadata.extend(bytes((-len(metadata)) % 8))
        field_ref_offset = len(metadata)
        metadata.extend(struct.pack("<ii", 17, 0))
        struct.pack_into("<II", metadata, 0xB8, field_ref_offset, 8)

        encoded = encode_field_info_usage_index(0, 31)
        with patch(
            "tools.il2cpp_network_callsite_evidence."
            "_metadata_usage_static_field_info_values",
            return_value={0x9000: encoded},
        ):
            report = inspect_bytes(bytes(metadata), make_elf(1))

        correlation = report["field_info_usage_correlation"]
        self.assertEqual(report["field_info_usage_static_cell_count"], 1)
        self.assertEqual(correlation["resolved_reference_count"], 1)
        self.assertEqual(correlation["unique_resolved_field_ref_count"], 1)
        self.assertEqual(
            correlation["references"][0],
            {
                "position": 0,
                "status": "field_ref_coordinate_resolved",
                "field_ref_index": 0,
                "type_index": 17,
                "field_index_within_type": 0,
            },
        )
        rendered = json.dumps(report)
        self.assertNotIn(hex(encoded), rendered)
        self.assertNotIn("0x9000", rendered)
        self.assertFalse(report["field_info_usage_cell_addresses_emitted"])
        self.assertFalse(report["native_addresses_emitted"])

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


    def test_login_request_serializer_fieldinfo_reaches_resolved_call_argument(self):
        metadata = bytearray(make_metadata(
            ["serialize", "SyntheticHelper"],
            image="ConvertedAssembly.dll",
            type_name="LoginRequestSTSerializer",
            namespace="com.geargames.serialization.serializers",
            fields=(("syntheticField", 17, 0x04000001),),
        ))
        metadata.extend(bytes((-len(metadata)) % 8))
        field_ref_offset = len(metadata)
        metadata.extend(struct.pack("<ii", 17, 0))
        struct.pack_into("<II", metadata, 0xB8, field_ref_offset, 8)

        encoded = encode_field_info_usage_index(0, 31)
        pc = 0x5000
        target_page = 0x3000
        page_delta = (target_page - (pc & ~0xFFF)) >> 12
        immediate = page_delta & ((1 << 21) - 1)
        adrp_x8 = (
            0x90000000
            | ((immediate & 0x3) << 29)
            | (((immediate >> 2) & 0x7FFFF) << 5)
            | 8
        )
        add_x8_x8_0x70 = 0x91000000 | (0x70 << 10) | (8 << 5) | 8
        ldr_x9_x8 = 0xF9400000 | (8 << 5) | 9
        mov_x1_x9 = 0xAA0003E0 | (9 << 16) | 1
        bl_synthetic_helper = 0x94000000 | 11  # PC 0x5010 -> entry 0x503C
        elf = make_elf(
            2,
            image="ConvertedAssembly.dll",
            text_words=(
                adrp_x8,
                add_x8_x8_0x70,
                ldr_x9_x8,
                mov_x1_x9,
                bl_synthetic_helper,
            ),
            method_entry_targets=(0x5000, 0x503C),
            field_info_token=encoded,
        )

        report = inspect_bytes(bytes(metadata), elf)
        self.assertEqual(report["selected_method_records"], 0)
        self.assertEqual(report["selected_login_request_method_records"], 1)
        self.assertEqual(report["resolved_login_request_entry_windows"], 1)
        self.assertEqual(report["callsite_summary"], [])
        self.assertEqual(len(report["login_request_callsite_summary"]), 1)

        login_entry = report["login_request_callsite_summary"][0]
        self.assertEqual(
            login_entry["control_flow_path_analysis_kind"],
            "bounded_simple_path_enumeration",
        )
        self.assertGreaterEqual(login_entry["control_flow_path_count"], 1)
        self.assertIsInstance(login_entry["control_flow_paths"], list)
        self.assertFalse(login_entry["control_flow_paths_truncated"])
        self.assertEqual(
            report["login_request_path_comparison"]["comparison_status"],
            "unpaired_or_ambiguous",
        )
        self.assertFalse(
            report["login_request_path_comparison"]["field_order_inferred"]
        )

        field_info_path = login_entry["field_info_path_correlation"]
        self.assertEqual(field_info_path["status"], "bounded")
        self.assertEqual(
            field_info_path["matched_unique_field_info_callsite_count"], 1
        )
        self.assertEqual(field_info_path["path_observation_match_count"], 1)
        path_matches = [
            path_observation
            for path in login_entry["control_flow_paths"]
            for path_observation in path["helper_callsite_observations"]
            if "field_info_arguments" in path_observation
        ]
        self.assertEqual(len(path_matches), 1)

        provenance = report["login_request_callsite_summary"][0][
            "field_info_call_argument_provenance"
        ]
        self.assertEqual(provenance["callsite_count"], 1)
        observation = provenance["callsite_observations"][0]
        self.assertEqual(
            path_matches[0]["field_info_arguments"],
            observation["field_info_arguments"],
        )
        self.assertEqual(
            observation["field_info_arguments"]["x1"],
            {
                "usage_occurrence_position": 0,
                "field_ref_index": 0,
                "type_index": 17,
                "field_index_within_type": 0,
            },
        )
        rendered = json.dumps(report)
        self.assertNotIn("0x5000", rendered)
        self.assertNotIn("0x3070", rendered)
        self.assertNotIn(hex(encoded), rendered)
        self.assertFalse(report["native_addresses_emitted"])
        self.assertFalse(report["raw_instructions_emitted"])

    def test_login_request_field_info_arguments_are_joined_to_matching_path_callsites(self):
        reference = {
            "usage_occurrence_position": 2,
            "field_ref_index": 7,
            "type_index": 11,
            "field_index_within_type": 3,
        }
        path_summary = {
            "control_flow_paths": [
                {
                    "exit_kind": "return",
                    "helper_callsite_observations": [
                        {
                            "kind": "direct_call",
                            "instruction_index": 4,
                            "method": "Example.LoginRequest::ReadField/p1",
                        },
                        {
                            "kind": "direct_call",
                            "instruction_index": 8,
                            "method": "Example.LoginRequest::Other/p0",
                        },
                    ],
                },
                {
                    "exit_kind": "branch_exit",
                    "helper_callsite_observations": [
                        {
                            "kind": "direct_call",
                            "instruction_index": 4,
                            "method": "Example.LoginRequest::ReadField/p1",
                        },
                    ],
                },
            ],
            "control_flow_path_count": 2,
            "control_flow_paths_truncated": False,
            "control_flow_path_analysis_status": "bounded",
        }
        field_info_summary = {
            "callsite_count": 1,
            "callsite_observations_truncated": False,
            "callsite_observations": [
                {
                    "instruction_index": 4,
                    "target_method": "Example.LoginRequest::ReadField",
                    "field_info_arguments": {"x0": reference},
                },
            ],
        }

        annotated, correlation = (
            _correlate_field_info_arguments_with_control_flow_paths(
                path_summary, field_info_summary
            )
        )
        first_calls = annotated["control_flow_paths"][0][
            "helper_callsite_observations"
        ]
        second_calls = annotated["control_flow_paths"][1][
            "helper_callsite_observations"
        ]
        self.assertEqual(first_calls[0]["field_info_arguments"], {"x0": reference})
        self.assertEqual(
            first_calls[0]["field_info_provenance"],
            "static_field_info_cell_to_direct_call_arguments",
        )
        self.assertNotIn("field_info_arguments", first_calls[1])
        self.assertEqual(second_calls[0]["field_info_arguments"], {"x0": reference})
        self.assertEqual(correlation["status"], "bounded")
        self.assertEqual(correlation["matched_unique_field_info_callsite_count"], 1)
        self.assertEqual(correlation["path_observation_match_count"], 2)
        self.assertFalse(correlation["field_order_inferred"])

    def test_login_request_field_info_path_join_rejects_method_label_mismatch(self):
        path_summary = {
            "control_flow_paths": [{
                "exit_kind": "return",
                "helper_callsite_observations": [{
                    "kind": "direct_call",
                    "instruction_index": 4,
                    "method": "Example.Other::ReadField/p1",
                }],
            }],
            "control_flow_path_count": 1,
            "control_flow_paths_truncated": False,
            "control_flow_path_analysis_status": "bounded",
        }
        field_info_summary = {
            "callsite_count": 1,
            "callsite_observations_truncated": False,
            "callsite_observations": [{
                "instruction_index": 4,
                "target_method": "Example.LoginRequest::ReadField",
                "field_info_arguments": {"x0": {
                    "usage_occurrence_position": 0,
                    "field_ref_index": 1,
                    "type_index": 2,
                    "field_index_within_type": 3,
                }},
            }],
        }

        annotated, correlation = (
            _correlate_field_info_arguments_with_control_flow_paths(
                path_summary, field_info_summary
            )
        )
        observation = annotated["control_flow_paths"][0][
            "helper_callsite_observations"
        ][0]
        self.assertNotIn("field_info_arguments", observation)
        self.assertEqual(correlation["path_method_mismatch_observation_count"], 1)
        self.assertEqual(correlation["unmatched_observed_field_info_callsite_count"], 1)
        self.assertEqual(correlation["status"], "partial")

    def test_login_request_field_info_path_join_keeps_duplicate_indexes_ambiguous(self):
        path_summary = {
            "control_flow_paths": [{
                "exit_kind": "return",
                "helper_callsite_observations": [{
                    "kind": "direct_call",
                    "instruction_index": 4,
                    "method": "Example.LoginRequest::ReadField/p1",
                }],
            }],
            "control_flow_path_count": 1,
            "control_flow_paths_truncated": False,
            "control_flow_path_analysis_status": "bounded",
        }
        reference = {
            "usage_occurrence_position": 0,
            "field_ref_index": 1,
            "type_index": 2,
            "field_index_within_type": 3,
        }
        field_info_summary = {
            "callsite_count": 2,
            "callsite_observations_truncated": False,
            "callsite_observations": [
                {
                    "instruction_index": 4,
                    "target_method": "Example.LoginRequest::ReadField",
                    "field_info_arguments": {"x0": reference},
                },
                {
                    "instruction_index": 4,
                    "target_method": "Example.LoginRequest::ReadField",
                    "field_info_arguments": {"x1": reference},
                },
            ],
        }

        annotated, correlation = (
            _correlate_field_info_arguments_with_control_flow_paths(
                path_summary, field_info_summary
            )
        )
        observation = annotated["control_flow_paths"][0][
            "helper_callsite_observations"
        ][0]
        self.assertNotIn("field_info_arguments", observation)
        self.assertEqual(correlation["ambiguous_field_info_callsite_count"], 1)
        self.assertEqual(correlation["ambiguous_path_observation_count"], 1)
        self.assertEqual(correlation["status"], "partial")

    def test_login_request_field_info_path_join_is_partial_for_truncated_inputs(self):
        path_summary = {
            "control_flow_paths": [{
                "exit_kind": "return",
                "helper_callsite_observations": [],
            }],
            "control_flow_path_count": 1,
            "control_flow_paths_truncated": True,
            "control_flow_path_analysis_status": "truncated",
        }
        field_info_summary = {
            "callsite_count": 2,
            "callsite_observations_truncated": True,
            "callsite_observations": [{
                "instruction_index": 4,
                "target_method": "Example.LoginRequest::ReadField",
                "field_info_arguments": {"x0": {
                    "usage_occurrence_position": 0,
                    "field_ref_index": 1,
                    "type_index": 2,
                    "field_index_within_type": 3,
                }},
            }],
        }

        _annotated, correlation = (
            _correlate_field_info_arguments_with_control_flow_paths(
                path_summary, field_info_summary
            )
        )
        self.assertEqual(correlation["status"], "partial")
        self.assertTrue(correlation["field_info_callsite_observations_truncated"])
        self.assertTrue(correlation["control_flow_paths_truncated"])

    def test_login_request_path_comparison_normalizes_primitive_helper_families(self):
        serializer = {
            "type": "LoginRequestSTSerializer",
            "method": "serialize",
            "entry_window_truncated": False,
            "control_flow_paths": [{
                "exit_kind": "return",
                "helper_callsite_observations": [{
                    "kind": "direct_call",
                    "method": "com.geargames.serialization.SimpleSerializer::serializeInt",
                }],
            }],
            "control_flow_path_count": 1,
            "control_flow_paths_truncated": False,
            "control_flow_path_analysis_status": "bounded",
        }
        deserializer = {
            "type": "LoginRequestSTDeserializer",
            "method": "deserialize",
            "entry_window_truncated": False,
            "control_flow_paths": [{
                "exit_kind": "return",
                "helper_callsite_observations": [{
                    "kind": "direct_call",
                    "method": "com.geargames.serialization.SimpleDeserializer::deserializeInt",
                }],
            }],
            "control_flow_path_count": 1,
            "control_flow_paths_truncated": False,
            "control_flow_path_analysis_status": "bounded",
        }

        comparison = _summarize_login_request_path_comparison(
            [serializer, deserializer]
        )
        self.assertEqual(comparison["comparison_status"], "bounded")
        self.assertEqual(comparison["path_pair_count"], 1)
        self.assertEqual(comparison["maximum_common_helper_prefix_length"], 1)
        self.assertFalse(comparison["field_order_inferred"])

    def test_login_request_path_comparison_is_partial_for_truncated_entry_window(self):
        serializer = {
            "type": "LoginRequestSTSerializer",
            "method": "serialize",
            "entry_window_truncated": True,
            "control_flow_paths": [],
            "control_flow_path_count": 0,
            "control_flow_paths_truncated": True,
            "control_flow_path_analysis_status": "cfg_truncated",
        }
        deserializer = {
            "type": "LoginRequestSTDeserializer",
            "method": "deserialize",
            "entry_window_truncated": False,
            "control_flow_paths": [],
            "control_flow_path_count": 0,
            "control_flow_paths_truncated": False,
            "control_flow_path_analysis_status": "empty",
        }

        comparison = _summarize_login_request_path_comparison(
            [serializer, deserializer]
        )
        self.assertEqual(comparison["comparison_status"], "partial")
        self.assertTrue(comparison["serializer_entry_window_truncated"])
        self.assertFalse(comparison["field_order_inferred"])

    def test_login_request_path_comparison_rejects_non_boolean_truncation_flags(self):
        serializer = {
            "type": "LoginRequestSTSerializer",
            "method": "serialize",
            "entry_window_truncated": 0,
        }
        deserializer = {
            "type": "LoginRequestSTDeserializer",
            "method": "deserialize",
            "entry_window_truncated": False,
        }
        with self.assertRaises(ValueError):
            _summarize_login_request_path_comparison([serializer, deserializer])

    def test_login_request_deserializer_is_included_but_other_login_types_are_not(self):
        for type_name, method_name, expected in (
            ("LoginRequestSTDeserializer", "deserialize", 1),
            ("LoginAnswerSTSerializer", "serialize", 0),
            ("SessionRestoreRequestSTSerializer", "serialize", 0),
        ):
            with self.subTest(type_name=type_name):
                report = inspect_bytes(
                    make_metadata(
                        [method_name],
                        image="ConvertedAssembly.dll",
                        type_name=type_name,
                        namespace="com.geargames.serialization.serializers",
                    ),
                    make_elf(1, image="ConvertedAssembly.dll"),
                )
                self.assertEqual(
                    report["selected_login_request_method_records"], expected
                )
                self.assertEqual(
                    len(report["login_request_callsite_summary"]), expected
                )

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
        self.assertEqual(report["selected_login_request_method_records"], 1)
        self.assertEqual(report["resolved_login_request_entry_windows"], 1)
        self.assertEqual(len(report["login_request_callsite_summary"]), 1)

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


    def test_inspect_bytes_can_resolve_fieldref_native_type_categories(self):
        metadata = bytearray(make_metadata(
            ["Cycle"],
            fields=[("probeField", 0, 0x04000001)],
        ))
        metadata.extend(bytes((-len(metadata)) % 8))
        field_ref_offset = len(metadata)
        metadata.extend(struct.pack("<ii", 0, 0))
        struct.pack_into("<II", metadata, 0xB8, field_ref_offset, 8)

        encoded = encode_field_info_usage_index(0, 31)
        elf = make_elf(
            1,
            include_native_type_table=True,
            field_info_token=encoded,
        )
        report = inspect_bytes(
            bytes(metadata), elf, resolve_fieldref_native_types=True
        )
        correlation = report["field_info_usage_correlation"]
        self.assertEqual(report["field_info_usage_static_cell_count"], 1)
        self.assertEqual(
            correlation["native_type_resolution"],
            {
                "status": "resolved",
                "type_table_count": 4,
                "unique_type_index_count": 1,
            },
        )
        self.assertEqual(
            correlation["references"][0]["native_type"],
            {"type_code": 0x08, "type_name": "I4"},
        )
        rendered = json.dumps(report)
        self.assertNotIn(hex(encoded), rendered)
        self.assertNotIn("0x3070", rendered)
        self.assertFalse(report["native_addresses_emitted"])


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


    def test_rejects_malformed_expected_fingerprint_before_path_access(self):
        for candidate in ("", "A" * 64, "g" * 64, 123):
            with self.subTest(candidate=repr(candidate)):
                with self.assertRaisesRegex(
                    CodegenInventoryError, "expected SHA-256"
                ):
                    _read_apk_members("/path/that/does/not/exist.apk", candidate)

    def test_expected_fingerprint_mismatch_fails_before_zip_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            self.write_apk(path)
            with patch(
                "tools.il2cpp_network_callsite_evidence.zipfile.ZipFile"
            ) as zip_file:
                with self.assertRaisesRegex(
                    CodegenInventoryError, "does not match expected fingerprint"
                ):
                    _read_apk_members(path, "0" * 64)
                zip_file.assert_not_called()

    def test_inspect_apk_accepts_matching_expected_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            self.write_apk(path, b"metadata", b"elf")
            expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch(
                "tools.il2cpp_network_callsite_evidence.inspect_bytes",
                return_value={"synthetic": True},
            ) as inspect:
                self.assertEqual(
                    inspect_apk(path, expected_sha256=expected_digest),
                    {"synthetic": True},
                )
            inspect.assert_called_once_with(b"metadata", b"elf", expected_digest)



    def test_inspect_apk_forwards_optional_fieldref_native_type_resolution(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            self.write_apk(path, b"metadata", b"elf")
            expected_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch(
                "tools.il2cpp_network_callsite_evidence.inspect_bytes",
                return_value={"synthetic": True},
            ) as inspect:
                self.assertEqual(
                    inspect_apk(
                        path,
                        expected_sha256=expected_digest,
                        resolve_fieldref_native_types=True,
                    ),
                    {"synthetic": True},
                )
            inspect.assert_called_once_with(
                b"metadata",
                b"elf",
                expected_digest,
                resolve_fieldref_native_types=True,
            )


    def test_inspect_apk_rejects_non_boolean_native_type_flag_before_reading(self):
        with patch(
            "tools.il2cpp_network_callsite_evidence._read_apk_members"
        ) as read_members:
            with self.assertRaisesRegex(
                CodegenInventoryError, "must be a built-in boolean"
            ):
                inspect_apk("/missing.apk", resolve_fieldref_native_types=1)
            read_members.assert_not_called()


if __name__ == "__main__":
    unittest.main()
