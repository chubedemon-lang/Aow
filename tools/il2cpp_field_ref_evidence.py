#!/usr/bin/env python3
"""Read-only IL2CPP v31 FieldRef table inventory for an authorized local APK.

A FieldRef record contains a TypeIndex and a field index local to that type.
This tool validates and reports those coordinates only. It does not resolve
native Il2CppType entries, infer a managed owner, or establish a native
callsite, packet field, runtime access, or APK/server compatibility.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

METADATA_MAGIC = 0xFAB11BAF
METADATA_VERSION = 31
HEADER_MIN_BYTES = 0x100
FIELD_REFS_PAIR_OFFSET = 0xB8
FIELD_REF_STRIDE = 8
MAX_FIELD_REFS = 1_000_000
MAX_REQUESTED_FIELD_REFS = 4096


class FieldRefEvidenceError(ValueError):
    """Malformed or unsupported IL2CPP FieldRef metadata."""


def _checked_field_ref_section(metadata: bytes) -> tuple[int, int, int]:
    if type(metadata) is not bytes:
        raise FieldRefEvidenceError("metadata must be exact immutable bytes")
    if len(metadata) < HEADER_MIN_BYTES:
        raise FieldRefEvidenceError("metadata v31 header is truncated")
    magic, version = struct.unpack_from("<II", metadata, 0)
    if magic != METADATA_MAGIC:
        raise FieldRefEvidenceError("invalid IL2CPP metadata magic")
    if version != METADATA_VERSION:
        raise FieldRefEvidenceError("expected IL2CPP metadata version 31")

    offset, size = struct.unpack_from(
        "<II", metadata, FIELD_REFS_PAIR_OFFSET
    )
    if (
        offset < HEADER_MIN_BYTES
        or size % FIELD_REF_STRIDE
        or offset + size < offset
        or offset + size > len(metadata)
    ):
        raise FieldRefEvidenceError("invalid FieldRef table bounds or record size")
    count = size // FIELD_REF_STRIDE
    if count > MAX_FIELD_REFS:
        raise FieldRefEvidenceError("FieldRef table exceeds configured limit")
    return offset, size, count


def _validate_requested_indexes(requested_indexes, count: int) -> tuple[int, ...]:
    if requested_indexes is None:
        return ()
    if type(requested_indexes) not in (list, tuple):
        raise FieldRefEvidenceError(
            "requested indexes must be a built-in list or tuple"
        )
    if len(requested_indexes) > MAX_REQUESTED_FIELD_REFS:
        raise FieldRefEvidenceError("requested FieldRef count exceeds configured limit")
    indexes = tuple(requested_indexes)
    if any(type(index) is not int or not 0 <= index < count for index in indexes):
        raise FieldRefEvidenceError("requested FieldRef index is outside the table")
    if len(set(indexes)) != len(indexes):
        raise FieldRefEvidenceError("requested FieldRef indexes contain duplicates")
    return indexes


def inspect_metadata(metadata: bytes, requested_indexes=None) -> dict:
    """Validate the v31 FieldRef table and optionally return selected records."""
    offset, _size, count = _checked_field_ref_section(metadata)
    requested = _validate_requested_indexes(requested_indexes, count)

    type_indexes = set()
    minimum_local_index = None
    maximum_local_index = None
    selected = {}
    requested_set = set(requested)

    for index in range(count):
        record_offset = offset + index * FIELD_REF_STRIDE
        type_index, local_field_index = struct.unpack_from(
            "<ii", metadata, record_offset
        )
        if type_index < 0:
            raise FieldRefEvidenceError("FieldRef TypeIndex is negative")
        if local_field_index < 0:
            raise FieldRefEvidenceError("FieldRef local field index is negative")
        type_indexes.add(type_index)
        minimum_local_index = (
            local_field_index if minimum_local_index is None
            else min(minimum_local_index, local_field_index)
        )
        maximum_local_index = (
            local_field_index if maximum_local_index is None
            else max(maximum_local_index, local_field_index)
        )
        if index in requested_set:
            selected[index] = {
                "field_ref_index": index,
                "type_index": type_index,
                "field_index_within_type": local_field_index,
            }

    return {
        "metadata_version": METADATA_VERSION,
        "field_ref_count": count,
        "unique_type_index_count": len(type_indexes),
        "minimum_local_field_index": minimum_local_index,
        "maximum_local_field_index": maximum_local_index,
        "requested_field_refs": [selected[index] for index in requested],
        "interpretation": (
            "Static FieldRef table coordinates only. TypeIndex still requires "
            "native Il2CppType-table resolution; field_index_within_type is a "
            "local field offset, not a global FieldDefinition index. This does "
            "not establish a native callsite, packet field, runtime access, "
            "wire contract, or APK/server compatibility."
        ),
    }


def inspect_apk(apk_path: str | Path, requested_indexes=None) -> dict:
    """Inspect the metadata member through the repository's stable APK reader."""
    from tools.il2cpp_metadata_inventory import _read_metadata

    metadata, apk_size, apk_sha256 = _read_metadata(Path(apk_path))
    report = inspect_metadata(metadata, requested_indexes)
    report.update({
        "apk_size_bytes": apk_size,
        "apk_sha256": apk_sha256,
    })
    return report


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="Read-only IL2CPP v31 FieldRef table inventory."
    )
    parser.add_argument("apk", help="path to an authorized local APK")
    parser.add_argument(
        "--field-ref-index",
        action="append",
        type=int,
        default=None,
        help="optional FieldRef index to include (may be repeated)",
    )
    parser.add_argument("--output", help="optional local JSON report path")
    args = parser.parse_args(argv)
    report = json.dumps(
        inspect_apk(args.apk, args.field_ref_index),
        indent=2,
        sort_keys=True,
    ) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
