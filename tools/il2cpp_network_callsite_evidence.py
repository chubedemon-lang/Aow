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
    _metadata_images,
    _slice,
)
from tools.aarch64_call_argument_evidence import (
    summarize_small_argument_constants,
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
}


def inspect_bytes(metadata, elf, apk_sha256=None):
    """Inspect metadata and arm64 IL2CPP bytes without publishing addresses."""
    info = _metadata_images(metadata)
    allowlist = dict(TARGET_METHODS)
    for key, names in NETWORK_SUPPORT_METHODS.items():
        allowlist[key] = set(allowlist.get(key, ())) | set(names)
    methods = [
        method for method in _network_methods(metadata, info, allowlist)
        if method["category"] != "login_session_serializer"
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
    unresolved_methods = 0
    direct_targets = set()
    indirect_targets = set()
    for method in methods:
        pointer_table = tables.get(method["image"])
        if pointer_table is None:
            unresolved_methods += 1
            continue
        slot = pointer_table + method["slot_index"] * 8
        relocation = relocations.get(slot)
        if relocation is None or relocation[0] != R_AARCH64_RELATIVE:
            unresolved_methods += 1
            continue
        target = relocation[1]
        matches = [
            (name, section) for name, section in executable
            if section["address"] <= target < section["address"] + section["size"]
        ]
        if len(matches) != 1:
            unresolved_methods += 1
            continue
        section_name, section = matches[0]
        window = windows.get((section_name, target))
        if window is None:
            unresolved_methods += 1
            continue
        window_bytes, truncated = window
        file_offset = section["offset"] + target - section["address"]
        code = _slice(elf, file_offset, window_bytes, "network method entry window")
        resolved.append((method, target, section_name, window_bytes, truncated, code))
        direct_targets.update(_direct_branch_targets(code, target))
        indirect_targets.update(
            _relocated_indirect_call_targets(code, target, relocations)
        )

    method_targets = _all_method_targets(
        metadata,
        info,
        tables,
        relocations,
        executable,
        direct_targets | indirect_targets,
    )

    callsite_summary = []
    for method, target, _section_name, window_bytes, truncated, code in resolved:
        direct = _summarize_named_method_calls(code, target, method_targets)
        indirect = _summarize_relocated_indirect_calls(
            code, target, relocations, method_targets
        )
        callsite_summary.append({
            "namespace": method["namespace"],
            "type": method["type"],
            "method": method["method"],
            "parameter_count": method["parameter_count"],
            "image": method["image"],
            "entry_window_kind": "next_distinct_executable_entry_in_section",
            "entry_window_bytes": window_bytes,
            "entry_window_truncated": truncated,
            **direct,
            **indirect,
            "linear_window_small_argument_observations": (
                summarize_small_argument_constants(
                    code,
                    target,
                    method_targets,
                    target_prefixes=(
                        "ClientNetworkStreamBuffer::SetDataAvailable",
                        "AbstractClientBuffer::Write",
                        "ClientStreamBuffer::Write",
                    ),
                )
            ),
        })
    callsite_summary.sort(key=lambda item: (
        item["namespace"], item["type"], item["method"],
        item["parameter_count"], item["image"],
    ))

    return {
        "apk_sha256": apk_sha256,
        "metadata_version": info["version"],
        "metadata_method_definitions": info["method_definitions"],
        "selected_method_records": len(methods),
        "resolved_entry_windows": len(resolved),
        "unresolved_method_records": unresolved_methods,
        "callsite_summary": callsite_summary,
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
        "packet_bytes_emitted": False,
        "interpretation": (
            "Aggregate AArch64 B/BL and conservative relocation-backed "
            "ADRP/ADD/LDR/BLR-or-BR callsite evidence from bounded native "
            "entry windows. A window ends at the next distinct executable "
            "method entry in the same section and may contain multiple control "
            "flow paths. Counts do not establish execution order, reachability, "
            "field meaning, packet framing, compression activation, message "
            "IDs, handshake semantics or APK/server compatibility."
        ),
    }


def inspect_apk(apk_path):
    """Read only bounded metadata and arm64 libil2cpp members from an APK."""
    path = Path(apk_path)
    if path.is_symlink() or not path.is_file():
        raise CodegenInventoryError("expected a regular local APK")
    if not 0 < path.stat().st_size <= MAX_APK:
        raise CodegenInventoryError("APK size outside safety bounds")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_info = archive.getinfo(METADATA_MEMBER)
            elf_info = archive.getinfo(ARM64_IL2CPP_MEMBER)
            if (metadata_info.file_size > MAX_METADATA
                    or elf_info.file_size > MAX_ELF):
                raise CodegenInventoryError("analysis member exceeds size limit")
            with archive.open(metadata_info) as member:
                metadata = member.read(MAX_METADATA + 1)
            with archive.open(elf_info) as member:
                elf = member.read(MAX_ELF + 1)
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        raise CodegenInventoryError("APK is missing valid IL2CPP members") from exc
    if len(metadata) > MAX_METADATA or len(elf) > MAX_ELF:
        raise CodegenInventoryError("analysis member exceeds size limit")
    return inspect_bytes(metadata, elf, digest.hexdigest())


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline redacted AOW native network callsite evidence"
    )
    parser.add_argument("apk", help="path to an authorized local APK")
    parser.add_argument("--output", help="write aggregate JSON to a local file")
    args = parser.parse_args(argv)
    report = json.dumps(inspect_apk(args.apk), indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
