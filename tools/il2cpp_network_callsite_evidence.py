"""Redacted native callsite inventory for AOW transport support methods.

This is a read-only offline analysis tool. It reports metadata method labels,
bounded entry-window sizes and aggregate call counts only. It never emits
native addresses, raw instructions, APK bytes, packet bytes or endpoints.

The bounded windows are not a control-flow graph: counts can include cold
branches, shared bodies or code after an early return. No wire semantics are
inferred from a callsite alone.
"""
import argparse
import hashlib
import json
import os
import stat
import struct
import zipfile
from pathlib import Path

from tools.il2cpp_codegen_inventory import (
    ARM64_IL2CPP_MEMBER,
    MAX_APK,
    MAX_ELF,
    MAX_METADATA,
    METADATA_MEMBER,
    R_AARCH64_RELATIVE,
    CodegenInventoryError,
    _contains,
    _metadata_images,
    _slice,
)
from tools.aarch64_call_return_evidence import summarize_immediate_call_result_zero_tests
from tools.aarch64_call_argument_evidence import (
    _method_name_from_label,
    summarize_small_argument_constants,
)
from tools.aarch64_memory_access_evidence import (
    summarize_control_flow_memory_accesses,
)
from tools.aarch64_memory_base_provenance import (
    summarize_control_flow_memory_base_provenance,
)
from tools.aarch64_field_info_call_arguments import (
    summarize_field_info_call_arguments,
)
from tools.aarch64_delegate_target_evidence import (
    summarize_delegate_constructor_argument_shape,
    summarize_delegate_method_pointer_arguments,
)
from tools.il2cpp_field_ref_evidence import correlate_field_info_usage_tokens
from tools.il2cpp_metadata_usage_evidence import (
    decode_field_info_usage_index,
    decode_method_def_usage_index,
    encode_method_def_usage_index,
)
from tools.il2cpp_native_method_evidence import (
    TARGET_METHODS,
    _all_method_targets,
    _direct_branch_targets,
    _entrypoint_windows,
    _module_tables,
    _network_methods,
    _relocated_indirect_call_targets,
    _summarize_named_method_calls,
    _summarize_relocated_indirect_calls,
    _summarize_control_flow_serializer_helper_blocks,
    _summarize_control_flow_helper_paths,
    _summarize_serializer_deserializer_path_alignment,
)

NETWORK_SUPPORT_METHODS = {
    ("com.geargames.common.utils", "ClientNetworkStreamBuffer"): {
        "SetDataAvailable", "ReadToEnd",
    },
    ("com.geargames.common.utils", "AbstractClientBuffer"): {
        "Write", "Read", "get_DataAvailable",
    },
    ("com.geargames.common.utils", "ClientByteBuffer"): {
        "GetBuffer", "ToStringAsSByte",
    },
    ("com.geargames.common.utils", "ClientStreamBuffer"): {"Write"},
    ("com.geargames.common.utils", "ClientArrayUtils"): {
        "ZipDecompress", "ZipCompression",
    },
    ("com.geargames.common.network", "ReceiverMessageQueue"): {
        "AddMessage", "GetMessage",
    },
    ("com.geargames.common.network", "SenderMessageQueue"): {
        "GetMessage", "SetConfirmedClientSequenceNumber",
        "SendMessageAsync", "get_Count",
    },
    ("com.geargames.common.network", "Sender"): {
        "GetMessageName", "CheckConnection",
    },
    ("com.geargames.serialization", "MessageMeta"): {".ctor"},
    ("com.geargames.common.network", "OnMessageReceivedDelegate"): {".ctor"},
}

# Keep only the exact LoginRequest serializer/deserializer pair in a separate
# report section. Other login/session serializers remain covered by the broader
# native-method analyzer and are not duplicated as transport callsite roots.
LOGIN_REQUEST_SERIALIZER_METHODS = frozenset({
    (
        "com.geargames.serialization.serializers",
        "LoginRequestSTSerializer",
        "serialize",
    ),
    (
        "com.geargames.serialization.serializers",
        "LoginRequestSTDeserializer",
        "deserialize",
    ),
})


def _metadata_usage_static_values_for_decoder(
    elf, sections, relocations, metadata_version, decoder,
):
    """Read relocation-referenced data cells accepted by one usage-token decoder."""
    values = {}
    data_sections = [
        sections[name]
        for name in (".data", ".data.rel.ro")
        if name in sections
    ]
    section_bytes = {
        section["address"]: _slice(
            elf, section["offset"], section["size"], "metadata-usage data section"
        )
        for section in data_sections
    }
    for relocation in relocations.values():
        if (
            not isinstance(relocation, tuple)
            or len(relocation) != 2
            or type(relocation[0]) is not int
            or relocation[0] != R_AARCH64_RELATIVE
            or type(relocation[1]) is not int
            or relocation[1] < 0
        ):
            continue
        target = relocation[1]
        # A cell with its own relocation is not a stable file-backed word.
        if target in relocations:
            continue
        for section in data_sections:
            if not _contains(section, target, 8):
                continue
            offset = target - section["address"]
            encoded = struct.unpack_from(
                "<Q", section_bytes[section["address"]], offset
            )[0]
            if encoded >> 32:
                break
            if decoder(encoded, metadata_version) is not None:
                values[target] = encoded
            break
    return values


def _metadata_usage_static_values(elf, sections, relocations, metadata_version):
    """Read relocation-backed cells containing resolved MethodDef usage tokens."""
    return _metadata_usage_static_values_for_decoder(
        elf, sections, relocations, metadata_version,
        decode_method_def_usage_index,
    )


def _metadata_usage_static_field_info_values(
    elf, sections, relocations, metadata_version,
):
    """Read relocation-backed cells containing resolved FieldInfo usage tokens."""
    return _metadata_usage_static_values_for_decoder(
        elf, sections, relocations, metadata_version,
        decode_field_info_usage_index,
    )

CALLSITE_ARGUMENT_TARGET_PREFIXES = (
    "ClientNetworkStreamBuffer::SetDataAvailable",
    "AbstractClientBuffer::Write",
    "ClientStreamBuffer::Write",
    "MessageDispatcher::SafeRegister",
)


def _summarize_login_request_path_comparison(callsite_summary):
    """Compare only the exact LoginRequest serializer/deserializer CFG paths."""
    if type(callsite_summary) is not list:
        raise ValueError("LoginRequest callsite summary must be a built-in list")
    serializers = []
    deserializers = []
    for entry in callsite_summary:
        if type(entry) is not dict:
            raise ValueError("LoginRequest callsite entries must be built-in dicts")
        if entry.get("type") == "LoginRequestSTSerializer" and entry.get("method") == "serialize":
            serializers.append(entry)
        elif entry.get("type") == "LoginRequestSTDeserializer" and entry.get("method") == "deserialize":
            deserializers.append(entry)

    if len(serializers) != 1 or len(deserializers) != 1:
        return {
            "comparison_kind": "login_request_bounded_control_flow_path_shape",
            "comparison_status": "unpaired_or_ambiguous",
            "serializer_entry_count": len(serializers),
            "deserializer_entry_count": len(deserializers),
            "field_order_inferred": False,
        }

    serializer_truncated = serializers[0].get("entry_window_truncated")
    deserializer_truncated = deserializers[0].get("entry_window_truncated")
    if type(serializer_truncated) is not bool or type(deserializer_truncated) is not bool:
        raise ValueError("LoginRequest entry-window truncation flags must be booleans")
    comparison = _summarize_serializer_deserializer_path_alignment(
        serializers[0], deserializers[0]
    )
    if serializer_truncated or deserializer_truncated:
        comparison["comparison_status"] = "partial"
    return {
        "comparison_kind": "login_request_bounded_control_flow_path_shape",
        "serializer_entry_count": 1,
        "deserializer_entry_count": 1,
        "serializer_entry_window_truncated": serializer_truncated,
        "deserializer_entry_window_truncated": deserializer_truncated,
        **comparison,
        "field_order_inferred": False,
    }


def _correlate_field_info_arguments_with_control_flow_paths(
    control_flow_path_summary, field_info_summary
):
    """Join exact FieldInfo argument provenance to matching CFG path callsites.

    The join requires the same instruction index within one bounded method
    window and the same canonical metadata method label. It annotates only
    uniquely matched direct calls; duplicate indexes, unresolved labels and
    mismatches remain unassigned. This is static register provenance, not a
    managed getter interpretation or serializer field order.
    """
    if type(control_flow_path_summary) is not dict:
        raise ValueError("control-flow path summary must be a built-in dict")
    if type(field_info_summary) is not dict:
        raise ValueError("FieldInfo provenance summary must be a built-in dict")

    paths = control_flow_path_summary.get("control_flow_paths")
    path_count = control_flow_path_summary.get("control_flow_path_count")
    paths_truncated = control_flow_path_summary.get(
        "control_flow_paths_truncated"
    )
    path_status = control_flow_path_summary.get(
        "control_flow_path_analysis_status"
    )
    if type(paths) is not list:
        raise ValueError("control-flow paths must be a built-in list")
    if type(path_count) is not int or path_count != len(paths):
        raise ValueError("control-flow path count does not match its list")
    if type(paths_truncated) is not bool:
        raise ValueError("control-flow path truncation flag must be a boolean")
    if type(path_status) is not str:
        raise ValueError("control-flow path status must be a string")

    field_observations = field_info_summary.get("callsite_observations")
    field_count = field_info_summary.get("callsite_count")
    field_truncated = field_info_summary.get(
        "callsite_observations_truncated"
    )
    if type(field_observations) is not list:
        raise ValueError("FieldInfo callsite observations must be a list")
    if (
        type(field_count) is not int
        or field_count < len(field_observations)
    ):
        raise ValueError("FieldInfo callsite count is inconsistent")
    if type(field_truncated) is not bool:
        raise ValueError("FieldInfo observation truncation flag must be a boolean")
    if field_truncated != (field_count > len(field_observations)):
        raise ValueError("FieldInfo observation truncation flag is inconsistent")

    field_by_index = {}
    duplicate_indexes = set()
    for observation in field_observations:
        if type(observation) is not dict:
            raise ValueError("FieldInfo callsite entries must be built-in dicts")
        instruction_index = observation.get("instruction_index")
        target_method = observation.get("target_method")
        arguments = observation.get("field_info_arguments")
        if type(instruction_index) is not int or instruction_index < 0:
            raise ValueError("FieldInfo instruction index must be non-negative")
        if type(target_method) is not str or not target_method:
            raise ValueError("FieldInfo target method must be a non-empty string")
        if type(arguments) is not dict or not arguments:
            raise ValueError("FieldInfo arguments must be a non-empty built-in dict")
        for register, reference in arguments.items():
            if register not in {f"x{index}" for index in range(8)}:
                raise ValueError("FieldInfo argument register is invalid")
            if type(reference) is not dict or set(reference) != {
                "usage_occurrence_position",
                "field_ref_index",
                "type_index",
                "field_index_within_type",
            }:
                raise ValueError("FieldInfo reference coordinates are malformed")
            if any(
                type(value) is not int or value < 0
                for value in reference.values()
            ):
                raise ValueError("FieldInfo reference coordinates must be non-negative")
        if instruction_index in field_by_index:
            duplicate_indexes.add(instruction_index)
            field_by_index.pop(instruction_index, None)
        elif instruction_index not in duplicate_indexes:
            field_by_index[instruction_index] = observation

    annotated_paths = []
    matched_indexes = set()
    path_observation_match_count = 0
    path_method_mismatch_count = 0
    ambiguous_path_observation_count = 0
    for path in paths:
        if type(path) is not dict:
            raise ValueError("control-flow path entries must be built-in dicts")
        observations = path.get("helper_callsite_observations")
        if type(observations) is not list:
            raise ValueError("path callsite observations must be a built-in list")
        annotated_observations = []
        for observation in observations:
            if type(observation) is not dict:
                raise ValueError("path callsite entries must be built-in dicts")
            annotated = dict(observation)
            instruction_index = observation.get("instruction_index")
            if (
                observation.get("kind") == "direct_call"
                and type(instruction_index) is int
            ):
                if instruction_index in duplicate_indexes:
                    ambiguous_path_observation_count += 1
                else:
                    field_observation = field_by_index.get(instruction_index)
                    if field_observation is not None:
                        path_method = _method_name_from_label(
                            observation.get("method")
                        )
                        if path_method != field_observation["target_method"]:
                            path_method_mismatch_count += 1
                        else:
                            annotated["field_info_arguments"] = dict(
                                field_observation["field_info_arguments"]
                            )
                            annotated["field_info_provenance"] = (
                                "static_field_info_cell_to_direct_call_arguments"
                            )
                            matched_indexes.add(instruction_index)
                            path_observation_match_count += 1
            annotated_observations.append(annotated)
        annotated_path = dict(path)
        annotated_path["helper_callsite_observations"] = annotated_observations
        annotated_paths.append(annotated_path)

    complete_path_statuses = {"bounded", "bounded_with_cycles", "empty"}
    unmatched_count = len(set(field_by_index) - matched_indexes)
    status = (
        "partial"
        if (
            field_truncated
            or paths_truncated
            or path_status not in complete_path_statuses
            or duplicate_indexes
            or path_method_mismatch_count
            or unmatched_count
        )
        else "bounded"
    )
    annotated_summary = dict(control_flow_path_summary)
    annotated_summary["control_flow_paths"] = annotated_paths
    correlation = {
        "analysis_kind": "same_method_instruction_index_and_method_label_join",
        "status": status,
        "reported_field_info_callsite_count": field_count,
        "observed_field_info_callsite_count": len(field_observations),
        "matched_unique_field_info_callsite_count": len(matched_indexes),
        "unmatched_observed_field_info_callsite_count": unmatched_count,
        "ambiguous_field_info_callsite_count": len(duplicate_indexes),
        "path_observation_match_count": path_observation_match_count,
        "path_method_mismatch_observation_count": path_method_mismatch_count,
        "ambiguous_path_observation_count": ambiguous_path_observation_count,
        "field_info_callsite_observations_truncated": field_truncated,
        "control_flow_paths_truncated": paths_truncated,
        "field_names_emitted": False,
        "native_addresses_emitted": False,
        "field_order_inferred": False,
    }
    return annotated_summary, correlation


def inspect_bytes(
    metadata, elf, apk_sha256=None, resolve_fieldref_native_types=False
):
    """Inspect native callsites and optionally resolve FieldRef type categories."""
    if type(resolve_fieldref_native_types) is not bool:
        raise CodegenInventoryError(
            "resolve_fieldref_native_types must be a built-in boolean"
        )
    info = _metadata_images(metadata)
    allowlist = dict(TARGET_METHODS)
    for key, names in NETWORK_SUPPORT_METHODS.items():
        allowlist[key] = set(allowlist.get(key, ())) | set(names)
    dispatcher_key = ("com.geargames.common.network", "MessageDispatcher")
    allowlist[dispatcher_key] = set(allowlist.get(dispatcher_key, ())) | {
        "SafeRegister",
    }
    # This async state machine owns the two connection-bootstrap listener
    # registrations observed in the original APK. Keep the root exact and
    # narrow; do not sweep every compiler-generated MoveNext method.
    allowlist[("", "<StartConnectToServer>d__12")] = {"MoveNext"}
    # Keep the two startup message callbacks explicit; their numeric registration
    # constants remain redacted from public reports.
    loading_presenter_key = (
        "com.geargames.aow.gui.loadingwindow",
        "GUILoadingPvpStartPresenter",
    )
    allowlist[loading_presenter_key] = set(
        allowlist.get(loading_presenter_key, ())
    ) | {"OnProgressAnswer", "OnProgressNotification"}
    all_methods = _network_methods(metadata, info, allowlist)
    methods = [
        method for method in all_methods
        if method["category"] != "login_session_serializer"
    ]
    login_request_methods = [
        method for method in all_methods
        if (
            method["namespace"], method["type"], method["method"]
        ) in LOGIN_REQUEST_SERIALIZER_METHODS
    ]

    sections, relocations, tables = _module_tables(elf, info["images"])
    executable = [
        (name, section) for name, section in sections.items()
        if section["type"] == 1 and (section["flags"] & 0x4)
    ]
    windows = _entrypoint_windows(
        sections, relocations, tables, info["images"], executable
    )

    resolved = []
    login_request_resolved = []
    unresolved_methods = 0
    unresolved_login_request_methods = 0
    direct_targets = set()
    indirect_targets = set()
    login_request_keys = {
        (method["namespace"], method["type"], method["method"])
        for method in login_request_methods
    }
    for method in methods + login_request_methods:
        pointer_table = tables.get(method["image"])
        is_login_request = (
            method["namespace"], method["type"], method["method"]
        ) in login_request_keys
        if pointer_table is None:
            if is_login_request:
                unresolved_login_request_methods += 1
            else:
                unresolved_methods += 1
            continue
        slot = pointer_table + method["slot_index"] * 8
        relocation = relocations.get(slot)
        if relocation is None or relocation[0] != R_AARCH64_RELATIVE:
            if is_login_request:
                unresolved_login_request_methods += 1
            else:
                unresolved_methods += 1
            continue
        target = relocation[1]
        matches = [
            (name, section) for name, section in executable
            if section["address"] <= target < section["address"] + section["size"]
        ]
        if len(matches) != 1:
            if is_login_request:
                unresolved_login_request_methods += 1
            else:
                unresolved_methods += 1
            continue
        section_name, section = matches[0]
        window = windows.get((section_name, target))
        if window is None:
            if is_login_request:
                unresolved_login_request_methods += 1
            else:
                unresolved_methods += 1
            continue
        window_bytes, truncated = window
        file_offset = section["offset"] + target - section["address"]
        code = _slice(elf, file_offset, window_bytes, "network method entry window")
        entry = (method, target, section_name, window_bytes, truncated, code)
        if is_login_request:
            login_request_resolved.append(entry)
        else:
            resolved.append(entry)
        direct_targets.update(_direct_branch_targets(code, target))
        indirect_targets.update(
            _relocated_indirect_call_targets(code, target, relocations)
        )

    static_memory_values = _metadata_usage_static_values(
        elf, sections, relocations, info["version"]
    )
    static_field_info_values = _metadata_usage_static_field_info_values(
        elf, sections, relocations, info["version"]
    )
    # Sort by private cell address for deterministic occurrence ordering. The
    # addresses are never copied into the public report.
    field_info_tokens = [
        static_field_info_values[address]
        for address in sorted(static_field_info_values)
    ]
    field_info_correlation = (
        correlate_field_info_usage_tokens(
            metadata,
            field_info_tokens,
            elf=elf if resolve_fieldref_native_types else None,
        )
        if field_info_tokens else None
    )
    # Keep cell addresses private to this offline pass. Occurrence order matches
    # the sorted static FieldInfo usage cells used to build field_info_tokens.
    field_info_cell_references = {}
    if field_info_correlation is not None:
        for address, reference in zip(
            sorted(static_field_info_values),
            field_info_correlation["references"],
        ):
            if reference["status"] == "field_ref_coordinate_resolved":
                field_info_cell_references[address] = (
                    reference["position"],
                    reference["field_ref_index"],
                    reference["type_index"],
                    reference["field_index_within_type"],
                )
    encoded_values = set(static_memory_values.values())
    image_starts = {
        image["name"]: image["method_start"]
        for image in info["images"]
        if image["method_start"] is not None
    }
    encoded_method_usage_targets = {}
    for method, target, _section_name, _window_bytes, _truncated, _code in (
        resolved + login_request_resolved
    ):
        image_start = image_starts.get(method["image"])
        if image_start is None:
            continue
        method_index = image_start + method["slot_index"]
        encoded_token = encode_method_def_usage_index(
            method_index, info["version"]
        )
        if encoded_token in encoded_values:
            encoded_method_usage_targets.setdefault(encoded_token, []).append(target)

    # _all_method_targets returns defaultdict(list). Materialize its
    # validated metadata associations as a plain dict before crossing the
    # strict AArch64 analyzer input boundary; do not expose __missing__ hooks.
    method_targets = dict(_all_method_targets(
        metadata,
        info,
        tables,
        relocations,
        executable,
        direct_targets | indirect_targets,
    ))
    # A delegate's method argument can point at an entrypoint that is not
    # itself called from the selected windows. Build a private lookup for all
    # validated metadata-backed entrypoints; only labels are emitted.
    all_entrypoint_targets = {target for _section_name, target in windows}
    # _all_method_targets returns defaultdict(list). Convert its fully
    # materialized metadata result to a plain dict before crossing the strict
    # analyzer input boundary; this avoids exposing a mapping with __missing__.
    delegate_method_targets = dict(_all_method_targets(
        metadata,
        info,
        tables,
        relocations,
        executable,
        all_entrypoint_targets,
    ))

    serializer_helper_prefixes = (
        "com.geargames.serialization.SimpleSerializer::",
        "com.geargames.serialization.SimpleDeserializer::",
    )
    serializer_helper_targets = {
        target: [
            label for label in labels
            if any(label.startswith(prefix) for prefix in serializer_helper_prefixes)
        ]
        for target, labels in method_targets.items()
        if any(
            label.startswith(prefix)
            for label in labels
            for prefix in serializer_helper_prefixes
        )
    }

    # Keep absolute relocation targets private to this analysis pass. The
    # downstream summary emits only symbolic provenance classes and relative
    # instruction indexes, never slot or target addresses.
    relative_relocation_targets = {
        slot: relocation[1]
        for slot, relocation in relocations.items()
        if (
            isinstance(relocation, tuple)
            and len(relocation) == 2
            and type(relocation[0]) is int
            and relocation[0] == R_AARCH64_RELATIVE
            and type(relocation[1]) is int
            and 0 <= relocation[1] <= 0xFFFFFFFFFFFFFFFF
        )
    }

    callsite_summary = []
    for method, target, _section_name, window_bytes, truncated, code in resolved:
        direct = _summarize_named_method_calls(code, target, method_targets)
        indirect = _summarize_relocated_indirect_calls(
            code, target, relocations, method_targets
        )
        record = {
            "namespace": method["namespace"],
            "type": method["type"],
            "method": method["method"],
            "parameter_count": method["parameter_count"],
            "image": method["image"],
            "entry_window_kind": "next_distinct_executable_entry_in_section",
            "entry_window_bytes": window_bytes,
            "entry_window_truncated": truncated,
            "immediate_call_result_zero_tests": (
                summarize_immediate_call_result_zero_tests(code)
            ),
            "cfg_memory_access_observations": (
                summarize_control_flow_memory_accesses(code, target)
            ),
            "cfg_memory_base_provenance_observations": (
                summarize_control_flow_memory_base_provenance(
                    code, target,
                    relocation_targets=relative_relocation_targets,
                    known_static_cells=(
                        tuple(sorted(static_field_info_values))
                        if resolve_fieldref_native_types else None
                    ),
                )
            ),
            **direct,
            **indirect,
            "linear_window_small_argument_observations": (
                summarize_small_argument_constants(
                    code,
                    target,
                    method_targets,
                    target_prefixes=CALLSITE_ARGUMENT_TARGET_PREFIXES,
                )
            ),
            "delegate_method_pointer_argument_observations": (
                summarize_delegate_method_pointer_arguments(
                    code,
                    target,
                    delegate_method_targets,
                    relocations,
                    target_prefixes=("OnMessageReceivedDelegate::.ctor",),
                    argument_registers=(2,),
                    static_memory_values=static_memory_values,
                    encoded_method_usage_targets=encoded_method_usage_targets,
                )
            ),
            "field_info_call_argument_provenance": (
                summarize_field_info_call_arguments(
                    code,
                    target,
                    method_targets,
                    field_info_cell_references,
                    relocation_targets=relative_relocation_targets,
                )
            ),
        }
        if (
            method["namespace"] == "com.geargames.common.network"
            and method["type"] == "OnMessageReceivedDelegate"
            and method["method"] == ".ctor"
        ):
            record["delegate_constructor_argument_shape"] = (
                summarize_delegate_constructor_argument_shape(code)
            )
        callsite_summary.append(record)
    callsite_summary.sort(key=lambda item: (
        item["namespace"], item["type"], item["method"],
        item["parameter_count"], item["image"],
    ))

    # Keep LoginRequest evidence separate from transport roots. This report
    # joins FieldInfo-derived FieldRef coordinates to x0-x7 only at uniquely
    # resolved direct calls; it does not infer managed field names or wire order.
    login_request_callsite_summary = []
    for method, target, _section_name, window_bytes, truncated, code in login_request_resolved:
        named_summary = _summarize_named_method_calls(code, target, method_targets)
        indirect_summary = _summarize_relocated_indirect_calls(
            code, target, relocations, method_targets
        )
        control_flow_summary = _summarize_control_flow_serializer_helper_blocks(
            code,
            target,
            relocations,
            serializer_helper_targets,
            method_targets=method_targets,
        )
        control_flow_path_summary = _summarize_control_flow_helper_paths(
            control_flow_summary
        )
        field_info_provenance = summarize_field_info_call_arguments(
            code,
            target,
            method_targets,
            field_info_cell_references,
            relocation_targets=relative_relocation_targets,
        )
        control_flow_path_summary, field_info_path_correlation = (
            _correlate_field_info_arguments_with_control_flow_paths(
                control_flow_path_summary, field_info_provenance
            )
        )
        login_request_callsite_summary.append({
            "type": method["type"],
            "method": method["method"],
            "image": method["image"],
            "entry_window_kind": "next_distinct_executable_entry_in_section",
            "entry_window_bytes": window_bytes,
            "entry_window_truncated": truncated,
            **named_summary,
            **indirect_summary,
            **control_flow_summary,
            **control_flow_path_summary,
            "field_info_call_argument_provenance": field_info_provenance,
            "field_info_path_correlation": field_info_path_correlation,
        })
    login_request_callsite_summary.sort(
        key=lambda item: (item["type"], item["method"], item["image"])
    )
    login_request_path_comparison = _summarize_login_request_path_comparison(
        login_request_callsite_summary
    )

    return {
        "apk_sha256": apk_sha256,
        "metadata_version": info["version"],
        "metadata_method_definitions": info["method_definitions"],
        "selected_method_records": len(methods),
        "resolved_entry_windows": len(resolved),
        "unresolved_method_records": unresolved_methods,
        "selected_login_request_method_records": len(login_request_methods),
        "resolved_login_request_entry_windows": len(login_request_resolved),
        "unresolved_login_request_method_records": unresolved_login_request_methods,
        "field_info_usage_static_cell_count": len(static_field_info_values),
        "field_info_usage_correlation": field_info_correlation,
        "field_info_usage_cell_addresses_emitted": False,
        "callsite_summary": callsite_summary,
        "login_request_callsite_summary": login_request_callsite_summary,
        "login_request_path_comparison": login_request_path_comparison,
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
        "packet_bytes_emitted": False,
        "interpretation": (
            "Aggregate AArch64 B/BL and conservative relocation-backed "
            "ADRP/ADD/LDR/BLR-or-BR callsite evidence plus bounded CFG-scoped "
            "memory-access and redacted base-register provenance observations. "
            "Memory-access reachability is structural only: both conditional "
            "outcomes are assumed and path conditions are not evaluated. "
            "Base provenance tracks only ADRP/ADD/MOV and explicitly supplied "
            "relative-relocation-backed 64-bit LDR chains; absolute addresses "
            "are not emitted. Windows may contain shared or cold code. These "
            "immediate post-call W0/X0 zero tests are structural register-use candidates, not "
            "callee return-type or semantic proof. These observations do not establish runtime execution, managed-field "
            "identity, packet framing, compression activation, message IDs, "
            "handshake semantics or APK/server compatibility. Relocation-backed "
            "FieldInfo usage cells are correlated to static FieldRef coordinates; "
            "the optional native-type flag adds only a symbolic Il2CppType "
            "category. Neither result identifies a managed owner or proves that "
            "a selected network method accesses the field. The separate "
            "LoginRequest summary adds static FieldInfo-to-argument coordinates "
            "for uniquely resolved direct calls plus bounded simple control-flow "
            "path-shape comparison for the exact serializer/deserializer pair. "
            "Conditional outcomes remain possible, cycles are not unrolled, and "
            "truncated windows produce partial comparisons. Path-shape similarity "
            "does not identify field names or serializer order."
        ),
    }


def _same_file_snapshot(before, after):
    """Compare identity and mutation-sensitive metadata for one open file."""
    return all(
        getattr(before, name, None) == getattr(after, name, None)
        for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _validate_expected_sha256(expected_sha256):
    """Validate an optional exact-build fingerprint before touching the APK."""
    if expected_sha256 is None:
        return
    if (type(expected_sha256) is not str
            or len(expected_sha256) != 64
            or any(char not in "0123456789abcdef" for char in expected_sha256)):
        raise CodegenInventoryError(
            "expected SHA-256 must be 64 lowercase hexadecimal characters"
        )


def _read_apk_members(apk_path, expected_sha256=None):
    """Read the bounded APK members through one stable, no-follow descriptor.

    Hashing and ZIP parsing share the same descriptor. This prevents a path
    replacement between the digest pass and member extraction from mixing
    evidence from two different APK files.
    """
    _validate_expected_sha256(expected_sha256)
    path = Path(apk_path)
    try:
        path_info = os.lstat(path)
    except OSError as exc:
        raise CodegenInventoryError("invalid or unsafe APK path") from exc
    if not stat.S_ISREG(path_info.st_mode):
        raise CodegenInventoryError("APK path must be a regular non-symlink file")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CodegenInventoryError("unable to open APK without following links") from exc

    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or not _same_file_snapshot(path_info, opened)):
            raise CodegenInventoryError("APK path changed before open")
        if not 0 < opened.st_size <= MAX_APK:
            raise CodegenInventoryError("invalid or oversized APK file")

        try:
            stream = os.fdopen(descriptor, "rb")
        except OSError as exc:
            raise CodegenInventoryError("unable to wrap stable APK descriptor") from exc
        descriptor = None
        with stream:
            digest = hashlib.sha256()
            remaining = opened.st_size
            while remaining:
                chunk = stream.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise CodegenInventoryError("APK was truncated while reading")
                digest.update(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise CodegenInventoryError("APK grew while reading")

            actual_digest = digest.hexdigest()
            if expected_sha256 is not None and actual_digest != expected_sha256:
                raise CodegenInventoryError(
                    "APK SHA-256 does not match expected fingerprint"
                )

            stream.seek(0)
            try:
                with zipfile.ZipFile(stream) as archive:
                    members = {}
                    for member_name in (METADATA_MEMBER, ARM64_IL2CPP_MEMBER):
                        matches = [
                            item for item in archive.infolist()
                            if item.filename == member_name
                        ]
                        if len(matches) != 1:
                            raise CodegenInventoryError(
                                "APK analysis members must exist exactly once"
                            )
                        members[member_name] = matches[0]

                    metadata_info = members[METADATA_MEMBER]
                    elf_info = members[ARM64_IL2CPP_MEMBER]
                    if (metadata_info.file_size > MAX_METADATA
                            or elf_info.file_size > MAX_ELF):
                        raise CodegenInventoryError(
                            "analysis member exceeds size limit"
                        )
                    with archive.open(metadata_info) as member:
                        metadata = member.read(MAX_METADATA + 1)
                    with archive.open(elf_info) as member:
                        elf = member.read(MAX_ELF + 1)
            except (KeyError, zipfile.BadZipFile, OSError, RuntimeError) as exc:
                raise CodegenInventoryError(
                    "APK is missing valid IL2CPP members"
                ) from exc

            if len(metadata) > MAX_METADATA or len(elf) > MAX_ELF:
                raise CodegenInventoryError("analysis member exceeds size limit")

            after = os.fstat(stream.fileno())
            if not _same_file_snapshot(opened, after):
                raise CodegenInventoryError("APK changed while reading")
            try:
                path_after = os.lstat(path)
            except OSError as exc:
                raise CodegenInventoryError("APK path changed while reading") from exc
            if (not stat.S_ISREG(path_after.st_mode)
                    or not _same_file_snapshot(opened, path_after)):
                raise CodegenInventoryError("APK path changed while reading")

            return actual_digest, metadata, elf
    except OSError as exc:
        raise CodegenInventoryError("unable to read stable APK file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def inspect_apk(
    apk_path, expected_sha256=None, resolve_fieldref_native_types=False
):
    """Read bounded APK members and optionally resolve FieldRef type categories."""
    if type(resolve_fieldref_native_types) is not bool:
        raise CodegenInventoryError(
            "resolve_fieldref_native_types must be a built-in boolean"
        )
    digest, metadata, elf = _read_apk_members(apk_path, expected_sha256)
    if resolve_fieldref_native_types:
        return inspect_bytes(
            metadata, elf, digest, resolve_fieldref_native_types=True
        )
    return inspect_bytes(metadata, elf, digest)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline redacted AOW native network callsite evidence"
    )
    parser.add_argument("apk", help="path to an authorized local APK")
    parser.add_argument("--output", help="write aggregate JSON to a local file")
    parser.add_argument(
        "--expected-sha256",
        help="require this exact lowercase SHA-256 before parsing APK members",
    )
    parser.add_argument(
        "--resolve-fieldref-native-types",
        action="store_true",
        help="resolve static FieldInfo-to-FieldRef TypeIndexes through the ARM64 native type table",
    )
    args = parser.parse_args(argv)
    report = json.dumps(
        inspect_apk(
            args.apk,
            expected_sha256=args.expected_sha256,
            resolve_fieldref_native_types=args.resolve_fieldref_native_types,
        ),
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
