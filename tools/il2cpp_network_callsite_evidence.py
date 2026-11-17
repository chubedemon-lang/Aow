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
from tools.aarch64_call_argument_evidence import (
    summarize_small_argument_constants,
)
from tools.aarch64_memory_access_evidence import (
    summarize_control_flow_memory_accesses,
)
from tools.aarch64_memory_base_provenance import (
    summarize_control_flow_memory_base_provenance,
)
from tools.aarch64_delegate_target_evidence import (
    summarize_delegate_constructor_argument_shape,
    summarize_delegate_method_pointer_arguments,
)
from tools.il2cpp_metadata_usage_evidence import (
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

def _metadata_usage_static_values(elf, sections, relocations, metadata_version):
    """Read only relocation-referenced data cells containing MethodDef usage tokens."""
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
            if decode_method_def_usage_index(encoded, metadata_version) is not None:
                values[target] = encoded
            break
    return values


CALLSITE_ARGUMENT_TARGET_PREFIXES = (
    "ClientNetworkStreamBuffer::SetDataAvailable",
    "AbstractClientBuffer::Write",
    "ClientStreamBuffer::Write",
    "MessageDispatcher::SafeRegister",
)


def inspect_bytes(metadata, elf, apk_sha256=None):
    """Inspect metadata and arm64 IL2CPP bytes without publishing addresses."""
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

    static_memory_values = _metadata_usage_static_values(
        elf, sections, relocations, info["version"]
    )
    encoded_values = set(static_memory_values.values())
    image_starts = {
        image["name"]: image["method_start"]
        for image in info["images"]
        if image["method_start"] is not None
    }
    encoded_method_usage_targets = {}
    for method, target, _section_name, _window_bytes, _truncated, _code in resolved:
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
            "cfg_memory_access_observations": (
                summarize_control_flow_memory_accesses(code, target)
            ),
            "cfg_memory_base_provenance_observations": (
                summarize_control_flow_memory_base_provenance(
                    code, target,
                    relocation_targets=relative_relocation_targets,
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
            "ADRP/ADD/LDR/BLR-or-BR callsite evidence plus bounded CFG-scoped "
            "memory-access and redacted base-register provenance observations. "
            "Memory-access reachability is structural only: both conditional "
            "outcomes are assumed and path conditions are not evaluated. "
            "Base provenance tracks only ADRP/ADD/MOV and explicitly supplied "
            "relative-relocation-backed 64-bit LDR chains; absolute addresses "
            "are not emitted. Windows may contain shared or cold code. These "
            "observations do not establish runtime execution, managed-field "
            "identity, packet framing, compression activation, message IDs, "
            "handshake semantics or APK/server compatibility."
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


def inspect_apk(apk_path, expected_sha256=None):
    """Read bounded IL2CPP members, optionally requiring an exact APK fingerprint."""
    digest, metadata, elf = _read_apk_members(apk_path, expected_sha256)
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
    args = parser.parse_args(argv)
    report = json.dumps(
        inspect_apk(args.apk, expected_sha256=args.expected_sha256),
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
