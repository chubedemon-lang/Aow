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

from tools.il2cpp_metadata_usage_evidence import decode_field_info_usage_index

METADATA_MAGIC = 0xFAB11BAF
METADATA_VERSION = 31
HEADER_MIN_BYTES = 0x100
FIELD_REFS_PAIR_OFFSET = 0xB8
FIELD_REF_STRIDE = 8
MAX_FIELD_REFS = 1_000_000
MAX_REQUESTED_FIELD_REFS = 4096
MAX_FIELD_INFO_USAGE_TOKENS = 4096
MAX_U32 = 0xFFFFFFFF


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


def _validate_field_info_tokens(encoded_tokens) -> tuple[int, ...]:
    if type(encoded_tokens) not in (list, tuple):
        raise FieldRefEvidenceError(
            "FieldInfo usage tokens must be a built-in list or tuple"
        )
    if len(encoded_tokens) > MAX_FIELD_INFO_USAGE_TOKENS:
        raise FieldRefEvidenceError(
            "FieldInfo usage token count exceeds configured limit"
        )
    tokens = tuple(encoded_tokens)
    if any(type(token) is not int or not 0 <= token <= MAX_U32 for token in tokens):
        raise FieldRefEvidenceError(
            "FieldInfo usage tokens must be unsigned 32-bit integers"
        )
    return tokens


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


def correlate_field_info_usage_tokens(metadata: bytes, encoded_tokens) -> dict:
    """Correlate bounded FieldInfo usage tokens with v31 FieldRef coordinates.

    Raw encoded tokens are deliberately omitted from the result. Unresolved
    tokens and indexes outside the FieldRef table remain explicit, non-resolved
    observations rather than being silently promoted to field references.
    """
    _offset, _size, field_ref_count = _checked_field_ref_section(metadata)
    tokens = _validate_field_info_tokens(encoded_tokens)
    decoded_indexes = [
        decode_field_info_usage_index(token, METADATA_VERSION)
        for token in tokens
    ]

    valid_indexes = sorted({
        index for index in decoded_indexes
        if index is not None and index < field_ref_count
    })
    table_report = inspect_metadata(metadata, valid_indexes)
    records_by_index = {
        record["field_ref_index"]: record
        for record in table_report["requested_field_refs"]
    }

    references = []
    unresolved_count = 0
    out_of_range_count = 0
    resolved_indexes = set()
    for position, field_ref_index in enumerate(decoded_indexes):
        if field_ref_index is None:
            unresolved_count += 1
            references.append({
                "position": position,
                "status": "unresolved_or_other_usage_type",
            })
        elif field_ref_index >= field_ref_count:
            out_of_range_count += 1
            references.append({
                "position": position,
                "status": "decoded_index_outside_field_ref_table",
                "field_ref_index": field_ref_index,
            })
        else:
            resolved_indexes.add(field_ref_index)
            references.append({
                "position": position,
                "status": "field_ref_coordinate_resolved",
                **records_by_index[field_ref_index],
            })

    return {
        "metadata_version": METADATA_VERSION,
        "field_ref_count": field_ref_count,
        "encoded_token_count": len(tokens),
        "resolved_reference_count": len(tokens) - unresolved_count - out_of_range_count,
        "unique_resolved_field_ref_count": len(resolved_indexes),
        "unresolved_or_other_usage_type_count": unresolved_count,
        "out_of_range_field_info_index_count": out_of_range_count,
        "no_out_of_range_resolved_indexes": out_of_range_count == 0,
        "references": references,
        "interpretation": (
            "Static FieldInfo metadata-usage token to FieldRef table-coordinate "
            "correlation only. Unresolved tokens are not classified further. "
            "This does not resolve native Il2CppType owners, prove a native "
            "callsite or runtime field access, identify packet fields, establish "
            "serializer order, or demonstrate a wire contract or APK/server "
            "compatibility."
        ),
    }


def inspect_apk(
    apk_path: str | Path,
    requested_indexes=None,
    encoded_field_info_tokens=None,
) -> dict:
    """Inspect APK metadata and optionally correlate supplied FieldInfo tokens."""
    from tools.il2cpp_metadata_inventory import _read_metadata

    metadata, apk_size, apk_sha256 = _read_metadata(Path(apk_path))
    report = inspect_metadata(metadata, requested_indexes)
    if encoded_field_info_tokens is not None:
        report["field_info_usage_correlation"] = (
            correlate_field_info_usage_tokens(metadata, encoded_field_info_tokens)
        )
    report.update({
        "apk_size_bytes": apk_size,
        "apk_sha256": apk_sha256,
    })
    return report


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="Read-only IL2CPP v31 FieldRef inventory and token correlation."
    )
    parser.add_argument("apk", help="path to an authorized local APK")
    parser.add_argument(
        "--field-ref-index",
        action="append",
        type=int,
        default=None,
        help="optional FieldRef index to include (may be repeated)",
    )
    parser.add_argument(
        "--field-info-usage-token",
        action="append",
        type=lambda value: int(value, 0),
        default=None,
        help="encoded FieldInfo usage token in decimal or 0x-prefixed hex (may repeat)",
    )
    parser.add_argument("--output", help="optional local JSON report path")
    args = parser.parse_args(argv)
    report = json.dumps(
        inspect_apk(
            args.apk,
            args.field_ref_index,
            args.field_info_usage_token,
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
