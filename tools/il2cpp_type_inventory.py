#!/usr/bin/env python3
"""Read-only IL2CPP v31 type/field/method name inventory for an authorized APK."""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from tools.il2cpp_metadata_inventory import (
    METADATA_MAGIC,
    SUPPORTED_METADATA_VERSION,
    MetadataInventoryError,
    _read_metadata,
)

HEADER_MIN_BYTES = 256
MAX_STRING_HEAP_BYTES = 64 * 1024**2
STRING_HEAP_PAIR_OFFSET = 24
METHODS_PAIR_OFFSET = 0x30
PARAMETERS_PAIR_OFFSET = 0x58
FIELDS_PAIR_OFFSET = 0x60
TYPE_DEFINITIONS_PAIR_OFFSET = 0xA0
TYPE_DEFINITION_STRIDE = 0x58
METHOD_DEFINITION_STRIDE = 0x24
FIELD_DEFINITION_STRIDE = 0x0C
PARAMETER_DEFINITION_STRIDE = 0x0C
FIELD_DEFAULT_VALUES_PAIR_OFFSET = 0x40
FIELD_DEFAULT_DATA_PAIR_OFFSET = 0x48
FIELD_DEFAULT_VALUE_STRIDE = 0x0C
MAX_DEFAULT_DATA_BYTES = 64 * 1024**2

MESSAGE_NAMES = (
    "LoginRequest", "LoginAnswer", "RegistrationRequest", "RegistrationAnswer",
    "SessionRestoreRequest", "SessionRestoreAnswer", "LoginToBattleRequest",
    "LoginToBattleAnswer", "BattleSessionRestoreRequest",
    "BattleSessionRestoreAnswer", "CheckSocket", "Ping",
)
MESSAGE_TYPE_FIELD_ALLOWLIST = frozenset({
    "LOGIN_REQUEST", "LOGIN_ANSWER", "REGISTRATION_REQUEST", "REGISTRATION_ANSWER",
    "SESSION_RESTORE_REQUEST", "SESSION_RESTORE_ANSWER",
    "LOGIN_TO_BATTLE_REQUEST", "LOGIN_TO_BATTLE_ANSWER",
    "BATTLE_SESSION_RESTORE_REQUEST", "BATTLE_SESSION_RESTORE_ANSWER",
    "PING", "CHECK_SOCKET", "BATTLE_LOAD_PROGRESS_REQUEST",
    "BATTLE_LOAD_PROGRESS_ANSWER", "START_BATTLE_NOTIFICATION",
    "BATTLE_FINISH_NOTIFICATION", "SHOP_BOX_REQUEST", "SHOP_BOX_ANSWER",
    "JOIN_PVE_MISSION_REQUEST", "JOIN_PVE_MISSION_ANSWER",
    "JOIN_PVP_MISSION_REQUEST", "JOIN_PVP_MISSION_ANSWER",
    "GO_TO_BATTLE_NOTIFICATION", "GO_TO_BATTLE_PROPOSAL",
    "GO_TO_BATTLE_CONFIRMATION", "BATTLE_AI_COMMAND_UNITS_MOVE",
    "BATTLE_AI_COMMAND_UNITS_STOP", "BATTLE_AI_COMMAND_UNITS_SPEC",
    "BATTLE_AI_COMMAND_BUILDING_SET", "LOBBY_CREATE_REQUEST",
    "LOBBY_CREATE_ANSWER", "MAP_BUNDLE_CI_REQUEST", "MAP_BUNDLE_CI_ANSWER",
})

TARGET_TYPES = {
    ("com.geargames.aow.messages", name) for name in MESSAGE_NAMES
}
TARGET_TYPES.add(("com.geargames.aow.messages", "MessageTypes"))
TARGET_TYPES.update({
    ("com.geargames.common.network", name) for name in (
        "INetwork", "Network", "NetworkSettings", "NetworkSocket",
        "Sender", "Receiver", "MessageDispatcher", "MessageHelper",
        "OnMessageReceivedDelegate",
    )
})
TARGET_TYPES.add(("", "NetworkSocketStream"))
TARGET_TYPES.add(("", "OnMessageReceivedDelegateData"))
TARGET_TYPES.update({
    ("com.geargames.common.serialization", "IClientMessageSerializer"),
    ("com.geargames.common.serialization", "IClientMessageDeserializer"),
    ("com.geargames.serialization", "MessageMeta"),
})
TARGET_TYPES.update({
    ("com.geargames.aow.config", name) for name in (
        "RemoteServerAddresses", "ServerAddressHelper",
        "ClientServerAddressConfiguration", "ClientServerPreset",
    )
})
TARGET_TYPES.update({
    ("com.geargames.unity.network", name) for name in (
        "CSAbstractSessionRestore`2", "CSMainSessionRestore",
        "CSBattleSessionRestore", "CSMainSessionRestoreAnswerReceiver",
        "CSBattleSessionRestoreAnswerReceiver",
        "CSAbstractSessionRestoreAnswerReceiver",
        "SessionRestoreStatusConverter",
    )
})
for _message_name in MESSAGE_NAMES:
    TARGET_TYPES.add((
        "com.geargames.serialization.serializers",
        _message_name + "STSerializer",
    ))
    TARGET_TYPES.add((
        "com.geargames.serialization.serializers",
        _message_name + "STDeserializer",
    ))


def _checked_section(metadata: bytes, pair_offset: int, stride: int, name: str):
    offset, size = struct.unpack_from("<II", metadata, pair_offset)
    if (
        offset < HEADER_MIN_BYTES
        or offset + size < offset
        or offset + size > len(metadata)
        or size % stride
    ):
        raise MetadataInventoryError(f"invalid {name} table bounds or record size")
    return offset, size, size // stride


def _read_heap_string(heap: bytes, index: int) -> str:
    if not 0 <= index < len(heap):
        raise MetadataInventoryError("metadata string index out of bounds")
    end = heap.find(b"\x00", index)
    if end < 0:
        raise MetadataInventoryError("unterminated metadata string")
    try:
        return heap[index:end].decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise MetadataInventoryError("invalid UTF-8 metadata string") from exc


def inspect_type_tables(apk_path: str | Path) -> dict:
    """Return allowlisted type, field-name and method-name associations."""
    metadata, apk_size, apk_sha256 = _read_metadata(Path(apk_path))
    if len(metadata) < HEADER_MIN_BYTES:
        raise MetadataInventoryError("metadata v31 header is truncated")
    magic, version = struct.unpack_from("<II", metadata, 0)
    if magic != METADATA_MAGIC:
        raise MetadataInventoryError("invalid IL2CPP metadata magic")
    if version != SUPPORTED_METADATA_VERSION:
        raise MetadataInventoryError("unsupported IL2CPP metadata version")

    string_offset, string_size = struct.unpack_from(
        "<II", metadata, STRING_HEAP_PAIR_OFFSET
    )
    if (
        string_offset < HEADER_MIN_BYTES
        or string_size <= 0
        or string_size > MAX_STRING_HEAP_BYTES
        or string_offset + string_size > len(metadata)
    ):
        raise MetadataInventoryError("invalid metadata string-heap bounds")
    heap = metadata[string_offset:string_offset + string_size]

    methods_offset, methods_size, method_count = _checked_section(
        metadata, METHODS_PAIR_OFFSET, METHOD_DEFINITION_STRIDE, "method"
    )
    parameters_offset, parameters_size, parameter_count = _checked_section(
        metadata, PARAMETERS_PAIR_OFFSET, PARAMETER_DEFINITION_STRIDE, "parameter"
    )
    field_defaults_offset, field_defaults_size, field_default_count = _checked_section(
        metadata, FIELD_DEFAULT_VALUES_PAIR_OFFSET, FIELD_DEFAULT_VALUE_STRIDE,
        "field default value"
    )
    default_data_offset, default_data_size = struct.unpack_from(
        "<II", metadata, FIELD_DEFAULT_DATA_PAIR_OFFSET
    )
    if (
        default_data_offset < HEADER_MIN_BYTES
        or default_data_size > MAX_DEFAULT_DATA_BYTES
        or default_data_offset + default_data_size < default_data_offset
        or default_data_offset + default_data_size > len(metadata)
    ):
        raise MetadataInventoryError("invalid field default data bounds")
    fields_offset, fields_size, field_count = _checked_section(
        metadata, FIELDS_PAIR_OFFSET, FIELD_DEFINITION_STRIDE, "field"
    )
    types_offset, types_size, type_count = _checked_section(
        metadata, TYPE_DEFINITIONS_PAIR_OFFSET, TYPE_DEFINITION_STRIDE, "type definition"
    )

    field_defaults = {}
    for default_index in range(field_default_count):
        default_pos = field_defaults_offset + default_index * FIELD_DEFAULT_VALUE_STRIDE
        field_index, default_type_index, data_index = struct.unpack_from(
            "<iii", metadata, default_pos
        )
        if field_index < 0 or field_index >= field_count:
            raise MetadataInventoryError("field default references unknown field")
        if data_index < 0 or data_index >= default_data_size:
            raise MetadataInventoryError("field default data index out of bounds")
        if field_index in field_defaults:
            raise MetadataInventoryError("duplicate field default record")
        field_defaults[field_index] = {
            "type_index": default_type_index,
            "data_index": data_index,
        }

    summaries = []
    for type_index in range(type_count):
        type_pos = types_offset + type_index * TYPE_DEFINITION_STRIDE
        name_index, namespace_index = struct.unpack_from("<II", metadata, type_pos)
        name = _read_heap_string(heap, name_index)
        namespace = _read_heap_string(heap, namespace_index)
        if (namespace, name) not in TARGET_TYPES:
            continue

        field_start, method_start = struct.unpack_from("<ii", metadata, type_pos + 0x20)
        method_n, _property_n, field_n = struct.unpack_from(
            "<HHH", metadata, type_pos + 0x40
        )
        if field_n and (field_start < 0 or field_start + field_n > field_count):
            raise MetadataInventoryError("target type field range out of bounds")
        if method_n and (method_start < 0 or method_start + method_n > method_count):
            raise MetadataInventoryError("target type method range out of bounds")

        field_records = []
        for field_index in range(field_start, field_start + field_n):
            field_pos = fields_offset + field_index * FIELD_DEFINITION_STRIDE
            field_name_index = struct.unpack_from("<I", metadata, field_pos)[0]
            field_type_index = struct.unpack_from("<i", metadata, field_pos + 4)[0]
            field_token = struct.unpack_from("<I", metadata, field_pos + 8)[0]
            default_value = field_defaults.get(field_index)
            field_records.append({
                "name": _read_heap_string(heap, field_name_index),
                "type_index": field_type_index,
                "metadata_token": field_token,
                "default_value_record_present": default_value is not None,
                "default_value_type_index": (
                    default_value["type_index"] if default_value is not None else None
                ),
                "default_value_data_index": (
                    default_value["data_index"] if default_value is not None else None
                ),
            })

        method_names = []
        method_records = []
        for method_index in range(method_start, method_start + method_n):
            method_pos = methods_offset + method_index * METHOD_DEFINITION_STRIDE
            method_name_index = struct.unpack_from("<I", metadata, method_pos)[0]
            declaring_type = struct.unpack_from("<i", metadata, method_pos + 4)[0]
            if declaring_type != type_index:
                raise MetadataInventoryError("target method declaring-type mismatch")
            return_type_index = struct.unpack_from("<i", metadata, method_pos + 8)[0]
            return_parameter_token = struct.unpack_from("<I", metadata, method_pos + 12)[0]
            parameter_start = struct.unpack_from("<i", metadata, method_pos + 16)[0]
            generic_container_index = struct.unpack_from("<i", metadata, method_pos + 20)[0]
            method_token = struct.unpack_from("<I", metadata, method_pos + 24)[0]
            flags, iflags, slot, method_parameter_count = struct.unpack_from(
                "<HHHH", metadata, method_pos + 28
            )
            parameters = []
            if method_parameter_count:
                if (
                    parameter_start < 0
                    or parameter_start + method_parameter_count > parameter_count
                ):
                    raise MetadataInventoryError("target method parameter range out of bounds")
                for parameter_index in range(
                    parameter_start, parameter_start + method_parameter_count
                ):
                    parameter_pos = (
                        parameters_offset + parameter_index * PARAMETER_DEFINITION_STRIDE
                    )
                    parameter_name_index = struct.unpack_from(
                        "<I", metadata, parameter_pos
                    )[0]
                    parameter_token = struct.unpack_from(
                        "<I", metadata, parameter_pos + 4
                    )[0]
                    parameter_type_index = struct.unpack_from(
                        "<i", metadata, parameter_pos + 8
                    )[0]
                    parameters.append({
                        "name": _read_heap_string(heap, parameter_name_index),
                        "type_index": parameter_type_index,
                        "metadata_token": parameter_token,
                    })
            method_name = _read_heap_string(heap, method_name_index)
            method_names.append(method_name)
            method_records.append({
                "name": method_name,
                "return_type_index": return_type_index,
                "return_parameter_token": return_parameter_token,
                "generic_container_index": generic_container_index,
                "metadata_token": method_token,
                "flags": flags,
                "iflags": iflags,
                "slot": slot,
                "parameters": parameters,
            })

        field_names_complete = True
        if namespace == "com.geargames.aow.messages" and name == "MessageTypes":
            field_records = [
                field for field in field_records
                if field["name"] in MESSAGE_TYPE_FIELD_ALLOWLIST
            ]
            field_names_complete = False
        field_names = [field["name"] for field in field_records]

        summaries.append({
            "namespace": namespace,
            "name": name,
            "field_count": field_n,
            "field_names": field_names,
            "field_records": field_records,
            "field_names_complete": field_names_complete,
            "method_count": method_n,
            "method_names": method_names,
            "method_records": method_records,
            "method_owner_matches": True,
        })

    summaries.sort(key=lambda item: (item["namespace"], item["name"]))
    return {
        "apk_size_bytes": apk_size,
        "apk_sha256": apk_sha256,
        "metadata_version": version,
        "metadata_table_counts": {
            "type_definitions": type_count,
            "methods": method_count,
            "parameters": parameter_count,
            "fields": field_count,
            "field_default_values": field_default_count,
            "field_default_data_bytes": default_data_size,
        },
        "observed_type_definitions": summaries,
        "interpretation": (
            "Static metadata type/field/method associations and raw type indexes only. "
            "Native type-index resolution, default-value decoding, method bodies, "
            "serialization order, numeric wire message IDs, framing, transport "
            "activation, and APK compatibility are not established."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only, offline IL2CPP v31 type/field/method inventory."
    )
    parser.add_argument("apk", help="Path to an authorized local APK")
    parser.add_argument("--output", help="Optional local JSON report path")
    args = parser.parse_args()
    report = json.dumps(inspect_type_tables(args.apk), indent=2, ensure_ascii=True)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)


if __name__ == "__main__":
    main()
