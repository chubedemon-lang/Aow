"""Redacted IL2CPP v31 native type and compressed integer default evidence.

The tool resolves allowlisted metadata type indexes through the arm64
Il2CppMetadataRegistration type-pointer table, then decodes only I4 defaults
using the v31 compressed signed-integer representation. It emits no native
addresses, raw default bytes, endpoints, packet contents or proprietary assets.
A decoded metadata default is static evidence, not proof of runtime use.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from tools.il2cpp_codegen_inventory import (
    R_AARCH64_RELATIVE,
    CodegenInventoryError,
    _elf_sections,
)
from tools.il2cpp_network_callsite_evidence import _read_apk_members

METADATA_MAGIC = 0xFAB11BAF
METADATA_VERSION = 31
HEADER_MIN_BYTES = 0x100
MAX_TABLE_RECORDS = 1_000_000
MAX_REQUESTED_TYPE_INDEXES = 4096
TYPE_NAMES = {
    0x00: "END", 0x01: "VOID", 0x02: "BOOLEAN", 0x03: "CHAR",
    0x04: "I1", 0x05: "U1", 0x06: "I2", 0x07: "U2",
    0x08: "I4", 0x09: "U4", 0x0A: "I8", 0x0B: "U8",
    0x0C: "R4", 0x0D: "R8", 0x0E: "STRING", 0x0F: "PTR",
    0x10: "BYREF", 0x11: "VALUETYPE", 0x12: "CLASS", 0x13: "VAR",
    0x14: "ARRAY", 0x15: "GENERICINST", 0x16: "TYPEDBYREF",
    0x18: "I", 0x19: "U", 0x1B: "FNPTR", 0x1C: "OBJECT",
    0x1D: "SZARRAY", 0x1E: "MVAR", 0x1F: "CMOD_REQD",
    0x20: "CMOD_OPT", 0x21: "INTERNAL", 0x40: "MODIFIER",
    0x41: "SENTINEL", 0x45: "PINNED", 0x55: "ENUM",
}
PRIMITIVE_TYPE_CODES = frozenset(range(0x02, 0x0F)) | {0x18, 0x19}
KNOWN_TYPE_CODES = frozenset(TYPE_NAMES)
TARGET_NAMESPACE = "com.geargames.common.network"
TARGET_TYPE = "NetworkSettings"
TARGET_FIELDS = (
    "SocketTimeoutDefault",
    "NetworkReadTimeout",
    "SocketAbortingTimeout",
    "ImmediatelyStopTimeout",
    "HeartbeatTimeoutDefault",
    "SocketReceiveBufferSize",
    "SocketSendBufferSize",
    "HeaderLength",
    "ZipIntermediateBufferSize",
    "ReceiverEncryptedBufferDefaultCapacity",
    "ReceiverEncryptedBufferMaxCapacity",
    "ReceiverDecryptedBufferDefaultCapacity",
    "ReceiverDecryptedBufferMaxCapacity",
    "ReceiverUnzippedBufferDefaultCapacity",
    "ReceiverUnzippedBufferMaxCapacityDefault",
    "SenderEncryptedBufferDefaultCapacity",
    "SenderEncryptedBufferMaxCapacity",
    "SenderDecryptedBufferDefaultCapacity",
    "SenderDecryptedBufferMaxCapacity",
    "SenderZippedBufferDefaultCapacity",
)


class DefaultValueEvidenceError(ValueError):
    """The supplied metadata or native registration is invalid or ambiguous."""


def decode_compressed_signed_int32(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode one canonical compressed signed integer using zigzag decoding."""
    if type(data) is not bytes:
        raise ValueError("default data must be exact immutable bytes")
    if type(offset) is not int or not 0 <= offset < len(data):
        raise ValueError("offset must point inside the default data")

    first = data[offset]
    if first & 0x80 == 0:
        encoded, width = first, 1
    elif first & 0xC0 == 0x80:
        if offset + 2 > len(data):
            raise ValueError("truncated two-byte compressed integer")
        encoded = ((first & 0x3F) << 8) | data[offset + 1]
        width = 2
        if encoded < 0x80:
            raise ValueError("non-canonical two-byte compressed integer")
    elif first & 0xE0 == 0xC0:
        if offset + 4 > len(data):
            raise ValueError("truncated four-byte compressed integer")
        encoded = (
            ((first & 0x1F) << 24)
            | (data[offset + 1] << 16)
            | (data[offset + 2] << 8)
            | data[offset + 3]
        )
        width = 4
        if encoded < 0x4000:
            raise ValueError("non-canonical four-byte compressed integer")
    else:
        raise ValueError("invalid compressed integer prefix")

    value = (encoded >> 1) ^ -(encoded & 1)
    if not -(1 << 31) <= value < (1 << 31):
        raise ValueError("decoded integer is outside signed 32-bit range")
    return value, width


def _section_for_address(sections, address: int, size: int = 1):
    for section in sections.values():
        if (
            section["type"] == 1
            and address >= section["address"]
            and size >= 0
            and address - section["address"] <= section["size"]
            and size <= section["size"] - (address - section["address"])
        ):
            return section
    return None


def _read_u64_at_va(elf: bytes, sections, address: int) -> int | None:
    section = _section_for_address(sections, address, 8)
    if section is None:
        return None
    offset = section["offset"] + address - section["address"]
    if offset < 0 or offset + 8 > len(elf):
        return None
    return struct.unpack_from("<Q", elf, offset)[0]


def _resolve_type_codes_from_tables(elf, sections, relocations, requested_indexes):
    """Resolve requested type indexes through one unique registration type table."""
    if type(elf) is not bytes:
        raise DefaultValueEvidenceError("ELF input must be exact immutable bytes")
    if type(sections) is not dict or type(relocations) is not dict:
        raise DefaultValueEvidenceError("ELF sections and relocations must be exact dicts")
    if type(requested_indexes) not in (list, tuple):
        raise DefaultValueEvidenceError(
            "requested type indexes must be a built-in list or tuple"
        )
    if not 1 <= len(requested_indexes) <= MAX_REQUESTED_TYPE_INDEXES:
        raise DefaultValueEvidenceError(
            "requested type index count is outside configured bounds"
        )
    indexes = tuple(requested_indexes)
    if any(
        type(index) is not int or not 0 <= index < MAX_TABLE_RECORDS
        for index in indexes
    ):
        raise DefaultValueEvidenceError("requested type indexes are invalid")
    if len(set(indexes)) != len(indexes):
        raise DefaultValueEvidenceError("requested type indexes contain duplicates")
    maximum_index = max(indexes)

    writable_sections = {
        name: section for name, section in sections.items()
        if section["type"] == 1 and (section["flags"] & 1)
    }
    slots_by_section = {name: [] for name in writable_sections}
    references_by_addend = {}
    for slot, relocation in relocations.items():
        if (
            type(slot) is not int or type(relocation) is not tuple
            or len(relocation) != 2 or relocation[0] != R_AARCH64_RELATIVE
            or type(relocation[1]) is not int or relocation[1] < 0
        ):
            continue
        references_by_addend.setdefault(relocation[1], []).append(slot)
        for name, section in writable_sections.items():
            if section["address"] <= slot < section["address"] + section["size"]:
                slots_by_section[name].append(slot)
                break

    candidates = {}
    for name, slots in slots_by_section.items():
        ordered = sorted(slots)
        run = []
        for slot in ordered + [None]:
            if slot is not None and (not run or slot == run[-1] + 8):
                run.append(slot)
                continue
            if maximum_index < len(run) <= MAX_TABLE_RECORDS:
                table_address = run[0]
                count = len(run)
                for reference in references_by_addend.get(table_address, ()):
                    reference_section = _section_for_address(
                        sections, reference - 8, 16
                    )
                    if (
                        reference_section is None
                        or not (reference_section["flags"] & 1)
                    ):
                        continue
                    registered_count = _read_u64_at_va(
                        elf, sections, reference - 8
                    )
                    if registered_count != count:
                        continue
                    type_codes = []
                    valid = True
                    for entry_slot in run:
                        relocation = relocations.get(entry_slot)
                        if relocation is None or relocation[0] != R_AARCH64_RELATIVE:
                            valid = False
                            break
                        target = relocation[1]
                        target_section = _section_for_address(sections, target, 12)
                        if target_section is None:
                            valid = False
                            break
                        target_offset = (
                            target_section["offset"] + target - target_section["address"]
                        )
                        if target_offset < 0 or target_offset + 12 > len(elf):
                            valid = False
                            break
                        packed = struct.unpack_from("<I", elf, target_offset + 8)[0]
                        type_code = (packed >> 16) & 0xFF
                        if type_code not in KNOWN_TYPE_CODES:
                            valid = False
                            break
                        type_codes.append(type_code)
                    if (
                        not valid or len(set(type_codes)) < 4
                        or not (set(type_codes) & PRIMITIVE_TYPE_CODES)
                    ):
                        continue
                    candidates[table_address] = (count, type_codes)
            run = [slot] if slot is not None else []

    if len(candidates) != 1:
        raise DefaultValueEvidenceError(
            "native Il2CppType registration table is missing or ambiguous"
        )
    count, type_codes = next(iter(candidates.values()))
    return {index: type_codes[index] for index in indexes}, count


def resolve_native_type_codes(elf: bytes, requested_indexes):
    """Resolve metadata type indexes to redacted Il2CppType enum names."""
    try:
        sections, relocations, _by_addend, _relative_offsets = _elf_sections(elf)
    except (CodegenInventoryError, KeyError, struct.error) as exc:
        raise DefaultValueEvidenceError("unable to parse arm64 IL2CPP ELF") from exc
    codes, count = _resolve_type_codes_from_tables(
        elf, sections, relocations, requested_indexes
    )
    return {
        "type_table_count": count,
        "types": {
            index: {
                "type_code": code,
                "type_name": TYPE_NAMES[code],
            }
            for index, code in codes.items()
        },
    }


def _checked_section(metadata, pair_offset, stride, label):
    offset, size = struct.unpack_from("<II", metadata, pair_offset)
    if (
        offset < HEADER_MIN_BYTES or size % stride
        or offset + size < offset or offset + size > len(metadata)
    ):
        raise DefaultValueEvidenceError(f"invalid {label} table bounds")
    return offset, size, size // stride


def _read_heap_string(heap, index):
    if not 0 <= index < len(heap):
        raise DefaultValueEvidenceError("metadata string index is out of bounds")
    end = heap.find(b"\x00", index)
    if end < 0:
        raise DefaultValueEvidenceError("metadata string is unterminated")
    try:
        return heap[index:end].decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise DefaultValueEvidenceError("metadata string is not valid UTF-8") from exc


def inspect_bytes(metadata: bytes, elf: bytes, apk_sha256=None) -> dict:
    """Inspect only the allowlisted NetworkSettings integer default values."""
    if type(metadata) is not bytes or type(elf) is not bytes:
        raise DefaultValueEvidenceError("metadata and ELF inputs must be exact bytes")
    if len(metadata) < HEADER_MIN_BYTES:
        raise DefaultValueEvidenceError("metadata header is truncated")
    magic, version = struct.unpack_from("<II", metadata, 0)
    if magic != METADATA_MAGIC or version != METADATA_VERSION:
        raise DefaultValueEvidenceError("expected IL2CPP metadata version 31")

    strings_offset, strings_size, _ = _checked_section(
        metadata, 0x18, 1, "string heap"
    )
    _checked_section(metadata, 0x30, 0x24, "method definitions")
    fields_offset, _fields_size, field_count = _checked_section(
        metadata, 0x60, 0x0C, "field definitions"
    )
    types_offset, _types_size, type_count = _checked_section(
        metadata, 0xA0, 0x58, "type definitions"
    )
    defaults_offset, _defaults_size, default_count = _checked_section(
        metadata, 0x40, 0x0C, "field default values"
    )
    data_offset, data_size = struct.unpack_from("<II", metadata, 0x48)
    if (
        data_offset < HEADER_MIN_BYTES or data_size > 64 * 1024 * 1024
        or data_offset + data_size < data_offset
        or data_offset + data_size > len(metadata)
    ):
        raise DefaultValueEvidenceError("invalid field-default data bounds")
    heap = metadata[strings_offset:strings_offset + strings_size]
    default_data = metadata[data_offset:data_offset + data_size]

    default_records = {}
    for record_index in range(default_count):
        field_index, default_type_index, data_index = struct.unpack_from(
            "<iii", metadata, defaults_offset + record_index * 0x0C
        )
        if not 0 <= field_index < field_count or default_type_index < 0:
            raise DefaultValueEvidenceError("invalid field-default table reference")
        if data_index < -1 or data_index >= data_size:
            raise DefaultValueEvidenceError("field-default data index is out of bounds")
        if field_index in default_records:
            raise DefaultValueEvidenceError("duplicate field-default record")
        default_records[field_index] = (record_index, default_type_index, data_index)

    target_types = []
    for type_index in range(type_count):
        record = types_offset + type_index * 0x58
        name_index, namespace_index = struct.unpack_from("<II", metadata, record)
        if (
            _read_heap_string(heap, name_index) == TARGET_TYPE
            and _read_heap_string(heap, namespace_index) == TARGET_NAMESPACE
        ):
            target_types.append((type_index, record))
    if len(target_types) != 1:
        raise DefaultValueEvidenceError("NetworkSettings type is missing or ambiguous")

    _declaring_type_index, type_record = target_types[0]
    field_start = struct.unpack_from("<i", metadata, type_record + 0x20)[0]
    field_count_in_type = struct.unpack_from("<H", metadata, type_record + 0x44)[0]
    if field_start < 0 or field_start + field_count_in_type > field_count:
        raise DefaultValueEvidenceError("NetworkSettings field range is invalid")

    selected = {}
    requested_type_indexes = set()
    for field_index in range(field_start, field_start + field_count_in_type):
        field_record = fields_offset + field_index * 0x0C
        name_index, field_type_index, _token = struct.unpack_from(
            "<IiI", metadata, field_record
        )
        field_name = _read_heap_string(heap, name_index)
        if field_name not in TARGET_FIELDS:
            continue
        if field_type_index < 0 or field_name in selected:
            raise DefaultValueEvidenceError("invalid or duplicate target field")
        default = default_records.get(field_index)
        if default is None:
            selected[field_name] = {
                "field_type_index": field_type_index,
                "default_record_present": False,
            }
            requested_type_indexes.add(field_type_index)
            continue
        record_index, default_type_index, data_index = default
        if data_index < 0:
            selected[field_name] = {
                "field_type_index": field_type_index,
                "default_record_present": True,
                "default_value_record_index": record_index,
                "default_type_index": default_type_index,
                "default_value": None,
                "decode_status": "explicit_null_or_missing_data",
            }
        else:
            selected[field_name] = {
                "field_type_index": field_type_index,
                "default_record_present": True,
                "default_value_record_index": record_index,
                "default_type_index": default_type_index,
                "data_index": data_index,
            }
        requested_type_indexes.add(field_type_index)
        requested_type_indexes.add(default_type_index)

    if set(TARGET_FIELDS) - set(selected):
        raise DefaultValueEvidenceError("one or more allowlisted fields are missing")
    resolved = resolve_native_type_codes(elf, sorted(requested_type_indexes))
    type_records = resolved["types"]
    output_fields = []
    for field_name in TARGET_FIELDS:
        item = selected[field_name]
        field_type = type_records[item["field_type_index"]]
        result = {
            "name": field_name,
            "field_type": field_type["type_name"],
            "default_record_present": item["default_record_present"],
        }
        if item["default_record_present"]:
            default_type = type_records[item["default_type_index"]]
            result["default_type"] = default_type["type_name"]
            result["default_value_record_index"] = item["default_value_record_index"]
            if item.get("data_index", -1) >= 0:
                if field_type["type_code"] != 0x08 or default_type["type_code"] != 0x08:
                    result["decode_status"] = "unsupported_type"
                else:
                    value, width = decode_compressed_signed_int32(
                        default_data, item["data_index"]
                    )
                    result["default_value"] = value
                    result["default_encoding"] = "compressed_signed_int32_zigzag"
                    result["encoded_width_bytes"] = width
            else:
                result["decode_status"] = item["decode_status"]
        output_fields.append(result)

    return {
        "apk_sha256": apk_sha256,
        "metadata_version": version,
        "native_type_table_count": resolved["type_table_count"],
        "fields": output_fields,
        "native_addresses_emitted": False,
        "raw_default_bytes_emitted": False,
        "interpretation": (
            "Allowlisted static metadata defaults decoded only after both the "
            "field and default type indexes resolve to native IL2CPP I4. This "
            "does not prove the default is applied at runtime, the field is read "
            "on the active transport path, or the value defines wire framing."
        ),
    }


def inspect_apk(apk_path, expected_sha256=None):
    """Inspect the metadata and arm64 IL2CPP members from one stable APK."""
    try:
        digest, metadata, elf = _read_apk_members(apk_path, expected_sha256)
    except CodegenInventoryError as exc:
        raise DefaultValueEvidenceError(str(exc)) from exc
    return inspect_bytes(metadata, elf, digest)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Redacted IL2CPP v31 compressed default-value evidence"
    )
    parser.add_argument("apk", help="path to an authorized local APK")
    parser.add_argument("--output", help="write aggregate JSON to a private local file")
    parser.add_argument("--expected-sha256", help="require an exact lowercase APK SHA-256")
    args = parser.parse_args(argv)
    report = json.dumps(
        inspect_apk(args.apk, args.expected_sha256), indent=2, sort_keys=True
    ) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
