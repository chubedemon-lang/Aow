"""Read-only native entry-point evidence for allowlisted IL2CPP network methods.

Only method names and relocation status are emitted. Native addresses, raw
instructions, packet bytes, endpoints and proprietary assets remain private.
This is static registration evidence, not a wire-protocol compatibility proof.
"""
import argparse
import bisect
import json
import struct
from collections import Counter, defaultdict

from tools.aarch64_eh_frame_index import (
    EhFrameIndexError, find_entry_window, parse_eh_frame_header,
)
from pathlib import Path

from tools.il2cpp_codegen_inventory import (
    R_AARCH64_RELATIVE, CodegenInventoryError, _contains, _elf_sections,
    _metadata_images, _read_apk_members, _slice, _table,
)

from tools.aarch64_memory_access_evidence import (
    summarize_unsigned_immediate_memory_accesses,
)

TARGET_METHODS = {
    ("com.geargames.common.network", "Network"): {
        "ConnectBeginAsync", "SendMessage", "ProcessingOneReceivedMessage",
        "ProcessingAllReceivedMessages",
    },
    ("com.geargames.common.network", "NetworkSettings"): {".cctor", ".ctor"},
    ("com.geargames.common.network", "Receiver"): {
        "Cycle", "DoStreamReadedBytes", "GetHttpMessageResponse",
        "ReadStreamBufferToEnd",
    },
    ("com.geargames.common.network", "Sender"): {
        "Cycle", "TrySendHeartbeat", "SerializedMessageTest",
    },
    ("com.geargames.common.network", "MessageHelper"): {
        "EnsureLoadDictionary", "InternalGetMessageType", "GetMessageType",
        "GetMessageTypeName", "GetMessageClassName",
    },
    ("com.geargames.common.network", "MessageDispatcher"): {
        "Dispatch", "TypeRegister",
    },
    ("", "NetworkSocketStream"): {"Read", "Write"},
    ("com.geargames.serialization.serializers", "LoginRequestSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "LoginRequestSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "LoginAnswerSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "LoginAnswerSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "RegistrationRequestSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "RegistrationRequestSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "RegistrationAnswerSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "RegistrationAnswerSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "SessionRestoreRequestSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "SessionRestoreRequestSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "SessionRestoreAnswerSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "SessionRestoreAnswerSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "LoginToBattleRequestSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "LoginToBattleRequestSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "LoginToBattleAnswerSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "LoginToBattleAnswerSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "BattleSessionRestoreRequestSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "BattleSessionRestoreRequestSTDeserializer"): {"deserialize"},
    ("com.geargames.serialization.serializers", "BattleSessionRestoreAnswerSTSerializer"): {"serialize"},
    ("com.geargames.serialization.serializers", "BattleSessionRestoreAnswerSTDeserializer"): {"deserialize"},
}

SERIALIZER_HELPER_METHODS = {
    ("com.geargames.serialization", "SimpleSerializer"): {
        "serializeInt", "serializeString", "serializeLong",
        "serializeBoolean", "serializeByte", "serializeChar", "serializeShort",
    },
    ("com.geargames.serialization", "SimpleDeserializer"): {
        "deserializeInt", "deserializeString", "deserializeLong",
        "deserializeBoolean", "deserializeByte", "deserializeChar",
        "deserializeShort", "deserializeChars",
    },
}

# Keep this list narrow: these entry windows are the network-path evidence
# used to summarize direct helper/method calls without emitting native addresses.
NETWORK_CALLSITE_METHODS = {
    # Include initialization roots so future offline runs can inspect the
    # bounded callsite windows that may populate NetworkSettings fields.
    # This does not resolve static-field loads/stores or runtime field values.
    ("com.geargames.common.network", "NetworkSettings", ".cctor"),
    ("com.geargames.common.network", "NetworkSettings", ".ctor"),
    ("com.geargames.common.network", "Receiver", "Cycle"),
    ("com.geargames.common.network", "Sender", "Cycle"),
    ("com.geargames.common.network", "MessageDispatcher", "Dispatch"),
    ("com.geargames.common.network", "MessageDispatcher", "TypeRegister"),
    ("com.geargames.common.network", "MessageHelper", "EnsureLoadDictionary"),
    ("com.geargames.common.network", "MessageHelper", "InternalGetMessageType"),
    ("com.geargames.common.network", "MessageHelper", "GetMessageType"),
    ("com.geargames.common.network", "MessageHelper", "GetMessageTypeName"),
    ("com.geargames.common.network", "MessageHelper", "GetMessageClassName"),
}

MAX_ENTRYPOINT_WINDOW_BYTES = 64 * 1024
MAX_SERIALIZER_ALIGNMENT_PATHS = 256
MAX_SERIALIZER_ALIGNMENT_OBSERVATIONS = MAX_ENTRYPOINT_WINDOW_BYTES // 4


def _network_methods(metadata, info, allowlist_map=None):
    if allowlist_map is None:
        allowlist_map = TARGET_METHODS
    string_off, string_size, _ = _table(metadata, 0x18, 1, "string heap")
    method_off, _, method_total = _table(metadata, 0x30, 0x24, "methods")
    type_off, _, type_total = _table(metadata, 0xA0, 0x58, "types")
    heap = _slice(metadata, string_off, string_size, "string heap")

    def read_string(index):
        if type(index) is not int or not 0 <= index < len(heap):
            raise CodegenInventoryError("invalid metadata string index")
        end = heap.find(b"\0", index)
        if end < 0:
            raise CodegenInventoryError("unterminated metadata string")
        try:
            return heap[index:end].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CodegenInventoryError("invalid metadata UTF-8") from exc

    image_ranges = [
        (x["name"], x["method_start"], x["method_count"])
        for x in info["images"]
        if x["method_start"] is not None and x["method_count"]
    ]
    records = []
    for type_index in range(type_total):
        pos = type_off + type_index * 0x58
        name_index, namespace_index = struct.unpack_from("<II", metadata, pos)
        name, namespace = read_string(name_index), read_string(namespace_index)
        allowlist = allowlist_map.get((namespace, name))
        if not allowlist:
            continue
        method_start = struct.unpack_from("<i", metadata, pos + 0x24)[0]
        method_count = struct.unpack_from("<H", metadata, pos + 0x40)[0]
        if (method_start < 0 or method_start > method_total
                or method_count > method_total - method_start):
            raise CodegenInventoryError("network type method range is invalid")
        for index in range(method_start, method_start + method_count):
            method_pos = method_off + index * 0x24
            name_index = struct.unpack_from("<I", metadata, method_pos)[0]
            owner = struct.unpack_from("<i", metadata, method_pos + 4)[0]
            if owner != type_index:
                raise CodegenInventoryError("network method owner mismatch")
            method_name = read_string(name_index)
            if method_name not in allowlist:
                continue
            parameter_count = struct.unpack_from("<H", metadata, method_pos + 34)[0]
            matches = [
                (image_name, image_start, image_count)
                for image_name, image_start, image_count in image_ranges
                if image_start <= index < image_start + image_count
            ]
            if len(matches) != 1:
                raise CodegenInventoryError("method does not map to one metadata image")
            image_name, image_start, _ = matches[0]
            records.append({
                "category": (
                    "login_session_serializer"
                    if namespace == "com.geargames.serialization.serializers"
                    else "serializer_helper"
                    if namespace == "com.geargames.serialization"
                    else "network"
                ),
                "namespace": namespace, "type": name, "method": method_name,
                "parameter_count": parameter_count, "image": image_name,
                "slot_index": index - image_start,
            })
    return records


NETWORK_FIELDS = {
    ("com.geargames.common.network", "NetworkSettings"): {
        "HeaderLength", "m_zippetMessageTypes", "m_notSessionedMessageTypes",
        "m_notEnumeratedMessageTypes", "m_unimportantMessageTypes",
    },
    ("com.geargames.common.network", "MessageHelper"): {
        "m_messageTypeByMessageClass", "m_messageClassByMessageType",
    },
}


def _network_fields(metadata, allowlist_map=None):
    """Summarize allowlisted network field names without exposing field values."""
    if allowlist_map is None:
        allowlist_map = NETWORK_FIELDS
    string_off, string_size, _ = _table(metadata, 0x18, 1, "string heap")
    field_off, _, field_total = _table(metadata, 0x60, 0x0C, "fields")
    default_off, _, default_total = _table(
        metadata, 0x40, 0x0C, "field default values"
    )
    type_off, _, type_total = _table(metadata, 0xA0, 0x58, "types")
    heap = _slice(metadata, string_off, string_size, "string heap")

    def read_string(index):
        if type(index) is not int or not 0 <= index < len(heap):
            raise CodegenInventoryError("invalid metadata string index")
        end = heap.find(b"\0", index)
        if end < 0:
            raise CodegenInventoryError("unterminated metadata string")
        try:
            return heap[index:end].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CodegenInventoryError("invalid metadata UTF-8") from exc

    default_fields = set()
    for index in range(default_total):
        field_index = struct.unpack_from(
            "<i", metadata, default_off + index * 0x0C
        )[0]
        if not 0 <= field_index < field_total:
            raise CodegenInventoryError("field default index is out of range")
        if field_index in default_fields:
            raise CodegenInventoryError("duplicate field default record")
        default_fields.add(field_index)

    records = []
    for type_index in range(type_total):
        type_pos = type_off + type_index * 0x58
        name_index, namespace_index = struct.unpack_from(
            "<II", metadata, type_pos
        )
        name = read_string(name_index)
        namespace = read_string(namespace_index)
        allowlist = allowlist_map.get((namespace, name))
        if not allowlist:
            continue
        field_start = struct.unpack_from("<i", metadata, type_pos + 0x20)[0]
        field_count = struct.unpack_from("<H", metadata, type_pos + 0x44)[0]
        if (field_start < 0 or field_start > field_total
                or field_count > field_total - field_start):
            raise CodegenInventoryError("network type field range is invalid")
        for field_index in range(field_start, field_start + field_count):
            field_pos = field_off + field_index * 0x0C
            field_name_index = struct.unpack_from("<I", metadata, field_pos)[0]
            field_type_index = struct.unpack_from("<i", metadata, field_pos + 4)[0]
            field_token = struct.unpack_from("<I", metadata, field_pos + 8)[0]
            field_name = read_string(field_name_index)
            if field_name not in allowlist:
                continue
            if field_type_index < 0:
                raise CodegenInventoryError("network field type index is negative")
            records.append({
                "namespace": namespace,
                "type": name,
                "field": field_name,
                "field_type_index": field_type_index,
                "token": hex(field_token),
                "has_default_value": field_index in default_fields,
            })
    records.sort(key=lambda item: (item["namespace"], item["type"], item["field"]))
    return records


def _module_tables(elf, images):
    sections, relocations, by_addend, _ = _elf_sections(elf)
    rodata, relro = sections[".rodata"], sections[".data.rel.ro"]
    ro = _slice(elf, rodata["offset"], rodata["size"], ".rodata")
    relro_data = _slice(elf, relro["offset"], relro["size"], ".data.rel.ro")
    writable = [
        x for x in sections.values()
        if x["type"] == 1 and (x["flags"] & 0x3) == 0x3
    ]
    tables = {}
    for image in images:
        if image["method_start"] is None or not image["method_count"]:
            continue
        needle = image["name"].encode("utf-8") + b"\0"
        candidates, cursor = [], 0
        while True:
            position = ro.find(needle, cursor)
            if position < 0:
                break
            cursor = position + 1
            name_address = rodata["address"] + position
            for module_address in by_addend.get(name_address, ()):
                if not _contains(relro, module_address, 24):
                    continue
                module_offset = module_address - relro["address"]
                count = struct.unpack_from("<I", relro_data, module_offset + 8)[0]
                if count != image["method_count"]:
                    continue
                pointer_relocation = relocations.get(module_address + 16)
                if (pointer_relocation is None
                        or pointer_relocation[0] != R_AARCH64_RELATIVE):
                    continue
                pointer_table = pointer_relocation[1]
                if any(_contains(x, pointer_table, count * 8) for x in writable):
                    candidates.append(pointer_table)
        if len(candidates) > 1:
            raise CodegenInventoryError("ambiguous codegen module")
        if candidates:
            tables[image["name"]] = candidates[0]
    return sections, relocations, tables



def _decode_aarch64_bl_target(word, pc):
    """Decode an AArch64 BL-immediate target; return None for other opcodes."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None
    if (word & 0xFC000000) != 0x94000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return pc + (immediate << 2)


def _all_method_targets(metadata, info, tables, relocations, executable, target_addresses):
    """Resolve selected direct-call destinations to metadata method labels only."""
    string_off, string_size, _ = _table(metadata, 0x18, 1, "string heap")
    method_off, _, method_total = _table(metadata, 0x30, 0x24, "methods")
    type_off, _, type_total = _table(metadata, 0xA0, 0x58, "types")
    heap = _slice(metadata, string_off, string_size, "string heap")

    def read_string(index):
        if type(index) is not int or not 0 <= index < len(heap):
            raise CodegenInventoryError("invalid metadata string index")
        end = heap.find(b"\0", index)
        if end < 0:
            raise CodegenInventoryError("unterminated metadata string")
        try:
            return heap[index:end].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CodegenInventoryError("invalid metadata UTF-8") from exc

    image_ranges = sorted(
        (item["method_start"], item["method_start"] + item["method_count"], item["name"])
        for item in info["images"]
        if item["method_start"] is not None and item["method_count"]
    )
    image_starts = [item[0] for item in image_ranges]
    targets = defaultdict(list)

    for type_index in range(type_total):
        type_pos = type_off + type_index * 0x58
        name_index, namespace_index = struct.unpack_from("<II", metadata, type_pos)
        type_name = read_string(name_index)
        namespace = read_string(namespace_index)
        method_start = struct.unpack_from("<i", metadata, type_pos + 0x24)[0]
        method_count = struct.unpack_from("<H", metadata, type_pos + 0x40)[0]
        if method_count == 0:
            continue
        if (method_start < 0 or method_start > method_total
                or method_count > method_total - method_start):
            raise CodegenInventoryError("type method range is invalid")

        for method_index in range(method_start, method_start + method_count):
            method_pos = method_off + method_index * 0x24
            method_name_index = struct.unpack_from("<I", metadata, method_pos)[0]
            owner = struct.unpack_from("<i", metadata, method_pos + 4)[0]
            if owner != type_index:
                raise CodegenInventoryError("method owner mismatch")
            method_name = read_string(method_name_index)
            parameter_count = struct.unpack_from("<H", metadata, method_pos + 34)[0]

            image_index = bisect.bisect_right(image_starts, method_index) - 1
            if image_index < 0:
                continue
            image_start, image_end, image_name = image_ranges[image_index]
            if not image_start <= method_index < image_end:
                continue
            pointer_table = tables.get(image_name)
            if pointer_table is None:
                continue
            relocation = relocations.get(
                pointer_table + (method_index - image_start) * 8
            )
            if relocation is None or relocation[0] != R_AARCH64_RELATIVE:
                continue
            target = relocation[1]
            if target not in target_addresses:
                continue
            matches = [
                section for _, section in executable
                if section["address"] <= target < section["address"] + section["size"]
            ]
            if len(matches) != 1:
                continue
            label = (
                f"{namespace + '.' if namespace else ''}"
                f"{type_name}::{method_name}/p{parameter_count}"
            )
            targets[target].append(label)

    return targets


def _decode_aarch64_b_target(word, pc):
    """Decode an AArch64 B-immediate target; return None for other opcodes."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None
    if (word & 0xFC000000) != 0x14000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return pc + (immediate << 2)



def _decode_aarch64_adr(word, pc):
    """Decode ADR into (destination register, byte address); otherwise None."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None
    if (word & 0x9F000000) != 0x10000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    destination = word & 0x1F
    if destination == 31:
        return None
    return destination, pc + immediate


def _decode_aarch64_adrp(word, pc):
    """Decode ADRP into (destination register, page address); otherwise None."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    if immediate & (1 << 20):
        immediate -= 1 << 21
    destination = word & 0x1F
    if destination == 31:
        return None
    return destination, (pc & ~0xFFF) + (immediate << 12)


def _decode_aarch64_add_imm64(word):
    """Decode 64-bit ADD-immediate without flags as (rd, rn, immediate)."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFF800000) != 0x91000000:
        return None
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    if destination == 31 or source == 31:
        return None
    return destination, source, immediate


def _decode_aarch64_ldr_x_unsigned(word):
    """Decode 64-bit unsigned-offset LDR as (rt, rn, byte_offset)."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFFC00000) != 0xF9400000:
        return None
    target = word & 0x1F
    base = (word >> 5) & 0x1F
    offset = ((word >> 10) & 0xFFF) * 8
    if target == 31 or base == 31:
        return None
    return target, base, offset


def _decode_aarch64_str_x_unsigned(word):
    """Decode 64-bit unsigned-offset STR as (rt, rn, byte_offset)."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFFC00000) != 0xF9000000:
        return None
    target = word & 0x1F
    base = (word >> 5) & 0x1F
    offset = ((word >> 10) & 0xFFF) * 8
    if target == 31 or base == 31:
        return None
    return target, base, offset


def _decode_aarch64_mov_w_register(word):
    """Decode the unshifted MOV Wd, Wm register alias."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word & 0x80000000:
        return None
    if (word & 0x7FE0FFE0) != 0x2A0003E0:
        return None
    destination = word & 0x1F
    source = (word >> 16) & 0x1F
    if destination == 31 or source == 31:
        return None
    return destination, source



def _skip_aarch64_nops(words, index):
    """Skip only architectural NOPs; unknown instructions remain barriers."""
    while index < len(words) and words[index][1] == 0xD503201F:
        index += 1
    return index


def _aarch64_global_cell_loads(code, start_va):
    """Find only adjacent ADRP/(NOP)/LDR same-register global-cell loads."""
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("AArch64 code window must be aligned bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be aligned")
    words = [
        (start_va + offset, struct.unpack_from("<I", code, offset)[0])
        for offset in range(0, len(code), 4)
    ]
    loads = []
    for index, (pc, word) in enumerate(words):
        adrp = _decode_aarch64_adrp(word, pc)
        if adrp is None:
            continue
        register, page = adrp
        following = _skip_aarch64_nops(words, index + 1)
        if following >= len(words):
            continue
        load = _decode_aarch64_ldr_x_unsigned(words[following][1])
        if load is None or load[0] != register or load[1] != register:
            continue
        loads.append({
            "cell": page + load[2],
            "register": register,
            "adrp_index": index,
            "load_index": following,
        })
    return loads

def _reachable_aarch64_instruction_indices(code, start_va):
    """Return conservative bounded CFG reachability from one entry instruction.

    Conditional branches retain both outcomes. Direct B follows only an
    in-window target; BL/BLR retain caller fallthrough. BR/RET and unrecognized
    branch-register-family instructions terminate the local walk rather than
    guessing a destination.
    """
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("AArch64 code window must be aligned built-in bytes")
    if len(code) > MAX_ENTRYPOINT_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the bounded method window")
    if (
        type(start_va) is not int
        or not 0 <= start_va <= 0xFFFFFFFFFFFFFFFF
        or start_va % 4
    ):
        raise ValueError("AArch64 code window start must be an aligned address")
    if code and start_va > 0xFFFFFFFFFFFFFFFF - (len(code) - 4):
        raise ValueError("AArch64 code window exceeds the unsigned address space")

    words = [
        struct.unpack_from("<I", code, offset)[0]
        for offset in range(0, len(code), 4)
    ]
    reachable = set()
    pending = [0] if words else []
    while pending:
        index = pending.pop()
        if index in reachable or not 0 <= index < len(words):
            continue
        reachable.add(index)
        word = words[index]
        pc = start_va + index * 4

        direct_branch = _decode_aarch64_b_target(word, pc)
        if direct_branch is not None:
            target_offset = direct_branch - start_va
            if 0 <= target_offset < len(code) and target_offset % 4 == 0:
                pending.append(target_offset // 4)
            continue

        conditional = _decode_aarch64_conditional_branch(word, pc)
        if conditional is not None:
            target_offset = conditional[1] - start_va
            if 0 <= target_offset < len(code) and target_offset % 4 == 0:
                pending.append(target_offset // 4)
            if index + 1 < len(words):
                pending.append(index + 1)
            continue

        if (
            _decode_aarch64_bl_target(word, pc) is not None
            or _decode_aarch64_blr_register(word) is not None
        ):
            if index + 1 < len(words):
                pending.append(index + 1)
            continue

        if (
            _decode_aarch64_br_register(word) is not None
            or _is_aarch64_return(word)
            or (word & 0xFE000000) in (0xD6000000, 0xD7000000)
        ):
            continue

        if index + 1 < len(words):
            pending.append(index + 1)

    return reachable


def _aarch64_instruction_reaches(code, start_va, source_index, target_index):
    """Return whether target_index is reachable from source_index in this window."""
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("AArch64 code window must be aligned built-in bytes")
    if len(code) > MAX_ENTRYPOINT_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the bounded method window")
    if (
        type(start_va) is not int
        or not 0 <= start_va <= 0xFFFFFFFFFFFFFFFF
        or start_va % 4
    ):
        raise ValueError("AArch64 code window start must be an aligned address")
    instruction_count = len(code) // 4
    if (
        type(source_index) is not int or type(target_index) is not int
        or not 0 <= source_index < instruction_count
        or not source_index <= target_index < instruction_count
    ):
        raise ValueError("instruction indexes must be ordered and inside the window")
    start_offset = source_index * 4
    end_offset = (target_index + 1) * 4
    bounded = code[start_offset:end_offset]
    reachable = _reachable_aarch64_instruction_indices(
        bounded, start_va + start_offset
    )
    return target_index - source_index in reachable


def _networksettings_static_first_slot_store_cells(code, start_va):
    """Find only reachable cctor class cells with a static_fields[0] store chain."""
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("NetworkSettings cctor code must be aligned AArch64 bytes")
    reachable = _reachable_aarch64_instruction_indices(code, start_va)
    words = [
        (start_va + offset, struct.unpack_from("<I", code, offset)[0])
        for offset in range(0, len(code), 4)
    ]
    cells = set()
    for load in _aarch64_global_cell_loads(code, start_va):
        if (
            load["adrp_index"] not in reachable
            or load["load_index"] not in reachable
        ):
            continue
        class_register = load["register"]
        first_index = _skip_aarch64_nops(words, load["load_index"] + 1)
        if first_index >= len(words) or first_index not in reachable:
            continue
        first = _decode_aarch64_ldr_x_unsigned(words[first_index][1])
        if first is None or first[1] != class_register or first[2] != 0:
            continue
        object_register = first[0]
        second_index = _skip_aarch64_nops(words, first_index + 1)
        if second_index >= len(words) or second_index not in reachable:
            continue
        second = _decode_aarch64_ldr_x_unsigned(words[second_index][1])
        if second is None or second[1] != object_register or second[2] != 0xB8:
            continue
        static_fields_register = second[0]
        store_index = _skip_aarch64_nops(words, second_index + 1)
        if store_index >= len(words) or store_index not in reachable:
            continue
        store = _decode_aarch64_str_x_unsigned(words[store_index][1])
        if store is not None and store[1] == static_fields_register and store[2] == 0:
            cells.add(load["cell"])
    return cells

def _networksettings_static_first_slot_read_sequences(code, start_va, expected_cell):
    """Find reachable three-load static_fields[0] reads after a class-cell load."""
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("AArch64 code window must be aligned bytes")
    reachable = _reachable_aarch64_instruction_indices(code, start_va)
    words = [
        (start_va + offset, struct.unpack_from("<I", code, offset)[0])
        for offset in range(0, len(code), 4)
    ]
    sequences = []
    for load in _aarch64_global_cell_loads(code, start_va):
        if (
            load["cell"] != expected_cell
            or load["adrp_index"] not in reachable
            or load["load_index"] not in reachable
        ):
            continue
        class_register = load["register"]
        for first_index in range(load["load_index"] + 1, min(load["load_index"] + 513, len(words))):
            if first_index not in reachable:
                continue
            first = _decode_aarch64_ldr_x_unsigned(words[first_index][1])
            if first is None or first[1] != class_register or first[2] != 0:
                continue
            object_register = first[0]
            second_index = _skip_aarch64_nops(words, first_index + 1)
            if second_index >= len(words) or second_index not in reachable:
                continue
            second = _decode_aarch64_ldr_x_unsigned(words[second_index][1])
            if second is None or second[1] != object_register or second[2] != 0xB8:
                continue
            static_fields_register = second[0]
            read_index = _skip_aarch64_nops(words, second_index + 1)
            if read_index >= len(words) or read_index not in reachable:
                continue
            third = _decode_aarch64_ldr_x_unsigned(words[read_index][1])
            if (
                third is not None and third[1] == static_fields_register
                and third[2] == 0
            ):
                sequences.append({
                    "load_index": load["load_index"],
                    "first_index": first_index,
                    "second_index": second_index,
                    "read_index": read_index,
                    "class_register": class_register,
                    "object_register": object_register,
                    "static_fields_register": static_fields_register,
                    "value_register": third[0],
                })
    return sequences

def _networksettings_first_non_default_field(metadata):
    """Return a metadata-order candidate, not a proven static-field map."""
    string_off, string_size, _ = _table(metadata, 0x18, 1, "string heap")
    field_off, _, field_total = _table(metadata, 0x60, 0x0C, "fields")
    default_off, _, default_total = _table(
        metadata, 0x40, 0x0C, "field default values"
    )
    type_off, _, type_total = _table(metadata, 0xA0, 0x58, "types")
    heap = _slice(metadata, string_off, string_size, "string heap")

    def read_string(index):
        if type(index) is not int or not 0 <= index < len(heap):
            raise ValueError("invalid NetworkSettings metadata string index")
        end = heap.find(b"\0", index)
        if end < 0:
            raise ValueError("unterminated NetworkSettings metadata string")
        try:
            return heap[index:end].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid NetworkSettings metadata UTF-8") from exc

    default_fields = set()
    for index in range(default_total):
        field_index = struct.unpack_from("<i", metadata, default_off + index * 0x0C)[0]
        if not 0 <= field_index < field_total:
            raise ValueError("field default index is out of range")
        if field_index in default_fields:
            raise ValueError("duplicate field default index")
        default_fields.add(field_index)

    matches = []
    for type_index in range(type_total):
        type_pos = type_off + type_index * 0x58
        name_index, namespace_index = struct.unpack_from("<II", metadata, type_pos)
        name = read_string(name_index)
        namespace = read_string(namespace_index)
        if name != "NetworkSettings" or namespace != "com.geargames.common.network":
            continue
        field_start = struct.unpack_from("<i", metadata, type_pos + 0x20)[0]
        field_count = struct.unpack_from("<H", metadata, type_pos + 0x44)[0]
        if (
            field_start < 0 or field_start > field_total
            or field_count > field_total - field_start
        ):
            raise ValueError("NetworkSettings field range is invalid")
        fields = []
        for field_index in range(field_start, field_start + field_count):
            field_name_index = struct.unpack_from("<I", metadata, field_off + field_index * 0x0C)[0]
            fields.append((read_string(field_name_index), field_index in default_fields))
        first = next(
            ((field_name, index) for index, (field_name, has_default) in enumerate(fields) if not has_default),
            None,
        )
        matches.append({
            "name": first[0] if first is not None else None,
            "leading_default_backed_field_count": first[1] if first is not None else len(fields),
            "field_count": len(fields),
        })
    return matches[0] if len(matches) == 1 else None



def _contains_hash_bucket_opcode_families(code):
    """Report broad opcode-family co-occurrence, not a hash-table data-flow shape."""
    if type(code) is not bytes or len(code) % 4:
        return False
    words = [
        struct.unpack_from("<I", code, offset)[0]
        for offset in range(0, len(code), 4)
    ]
    return (
        any((word & 0x7FE0FC00) == 0x1AC00C00 for word in words)
        and any((word & 0x7FE08000) == 0x1B008000 for word in words)
        and any((word & 0xFFC00000) == 0xB9400000 for word in words)
        and any((word & 0x7F20001F) == 0x6B00001F for word in words)
        and any((word & 0xFF000010) == 0x54000000 for word in words)
    )


def _decode_aarch64_sdiv_w(word):
    """Decode 32-bit SDIV as (destination, dividend, divisor)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or word & (1 << 31)
        or (word & 0x7FE0FC00) != 0x1AC00C00
    ):
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F


def _decode_aarch64_msub_w(word):
    """Decode 32-bit MSUB as (destination, left, right, addend)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or word & (1 << 31)
        or (word & 0x7FE08000) != 0x1B008000
    ):
        return None
    return (
        word & 0x1F,
        (word >> 5) & 0x1F,
        (word >> 16) & 0x1F,
        (word >> 10) & 0x1F,
    )


def _decode_aarch64_cmp_w_register(word):
    """Decode CMP Wn, Wm as (left, right)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or (word & 0xFF20001F) != 0x6B00001F
    ):
        return None
    return (word >> 5) & 0x1F, (word >> 16) & 0x1F


def _decode_aarch64_add_x_w_uxtw(word):
    """Decode ADD Xd, Xn, Wm, UXTW #shift."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or (word & 0xFFE00000) != 0x8B200000
    ):
        return None
    return (
        word & 0x1F,
        (word >> 5) & 0x1F,
        (word >> 16) & 0x1F,
        (word >> 13) & 0x7,
        (word >> 10) & 0x7,
    )


def _decode_aarch64_ldr_w_unsigned(word):
    """Decode LDR Wt, [Xn, #offset] as (target, base, byte_offset)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or (word & 0xFFC00000) != 0xB9400000
    ):
        return None
    return word & 0x1F, (word >> 5) & 0x1F, ((word >> 10) & 0xFFF) * 4


def _decode_aarch64_subs_w_immediate(word):
    """Decode 32-bit SUBS immediate as (destination, source, immediate)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or (word & 0xFF800000) != 0x71000000
    ):
        return None
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    return word & 0x1F, (word >> 5) & 0x1F, immediate


def _decode_aarch64_movz_w_immediate(word):
    """Decode MOVZ Wd, #imm16 as (destination, immediate)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or word & (1 << 31)
        or (word & 0x7F800000) != 0x52800000
        or ((word >> 21) & 0x3) != 0
    ):
        return None
    return word & 0x1F, (word >> 5) & 0xFFFF


def _decode_aarch64_umaddl(word):
    """Decode UMADDL/UMULL as (destination, left, right, addend)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or (word & 0xFFE08000) != 0x9BA00000
    ):
        return None
    return (
        word & 0x1F,
        (word >> 5) & 0x1F,
        (word >> 16) & 0x1F,
        (word >> 10) & 0x1F,
    )


def _decode_aarch64_ldr_w_register(word):
    """Decode unshifted LDR Wt, [Xn, Xm] as (target, base, index)."""
    if (
        type(word) is not int or not 0 <= word <= 0xFFFFFFFF
        or (word & 0xFFE0FC00) != 0xB8606800
    ):
        return None
    option = (word >> 13) & 0x7
    scaled = bool(word & (1 << 12))
    if option != 0x3 or scaled:
        return None
    return word & 0x1F, (word >> 5) & 0x1F, (word >> 16) & 0x1F


def _summarize_bucketed_lookup_shape(code):
    """Recognize a narrow bucket/hash/entry-chain lookup shape without naming its owner.

    The matcher requires register-linked modulo bucket selection, a bucket-head
    sentinel, a 12-byte entry stride, stored-hash comparison, an indirect
    comparer call, and a next-entry index load. It does not identify the
    managed generic method, collection field, key semantics, or runtime path.
    """
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("bucketed lookup code must be aligned AArch64 bytes")
    if len(code) > MAX_ENTRYPOINT_WINDOW_BYTES:
        raise ValueError("bucketed lookup code exceeds the bounded method window")
    words = [
        struct.unpack_from("<I", code, offset)[0]
        for offset in range(0, len(code), 4)
    ]

    def skip_nops(index):
        while index < len(words) and words[index] == 0xD503201F:
            index += 1
        return index

    def is_scan_barrier(word):
        # A linear candidate must not borrow instructions from another block or
        # carry unmodeled state across a call. Conditional branches are retained
        # as possible fallthrough edges; their runtime predicate is not evaluated.
        return (
            _decode_aarch64_bl_target(word, 0) is not None
            or _decode_aarch64_b_target(word, 0) is not None
            or _decode_aarch64_blr_register(word) is not None
            or _decode_aarch64_br_register(word) is not None
            or _is_aarch64_return(word)
            or (word & 0xFE000000) in (0xD6000000, 0xD7000000)
        )

    def find_after(start, decoder, predicate, limit=128):
        end = min(len(words), start + limit)
        for index in range(start, end):
            if is_scan_barrier(words[index]):
                return None, None
            decoded = decoder(words[index])
            if decoded is not None and predicate(decoded):
                return index, decoded
        return None, None

    # Share the repository's conservative CFG walker so this matcher also
    # terminates at unrecognized D6/D7 branch-register-family instructions.
    # Conditional edges remain possible; no predicate or target is guessed.
    reachable = _reachable_aarch64_instruction_indices(code, 0)

    unresolved = {
        "status": "unresolved",
        "managed_method_identity_verified": False,
        "managed_collection_owner_verified": False,
    }

    for divide_index, word in enumerate(words):
        if divide_index not in reachable:
            continue
        divide = _decode_aarch64_sdiv_w(word)
        if divide is None:
            continue
        quotient, dividend, divisor = divide

        msub_index = skip_nops(divide_index + 1)
        if msub_index >= len(words):
            continue
        msub = _decode_aarch64_msub_w(words[msub_index])
        if msub is None:
            continue
        remainder, left, right, addend = msub
        if (left, right, addend) != (quotient, divisor, dividend):
            continue

        compare_index = skip_nops(msub_index + 1)
        compare = (
            _decode_aarch64_cmp_w_register(words[compare_index])
            if compare_index < len(words) else None
        )
        if compare != (remainder, divisor):
            continue

        bucket_branch_index = skip_nops(compare_index + 1)
        bucket_branch = (
            _decode_aarch64_conditional_branch_condition(words[bucket_branch_index])
            if bucket_branch_index < len(words) else None
        )
        if (
            bucket_branch is None or bucket_branch.get("kind") != "b_cond"
            or bucket_branch.get("condition_code") != 2
        ):
            continue

        bucket_add_index = skip_nops(bucket_branch_index + 1)
        bucket_add = (
            _decode_aarch64_add_x_w_uxtw(words[bucket_add_index])
            if bucket_add_index < len(words) else None
        )
        if (
            bucket_add is None or bucket_add[2] != remainder
            or bucket_add[3:] != (2, 2)
        ):
            continue
        bucket_address = bucket_add[0]

        head_index = skip_nops(bucket_add_index + 1)
        head_load = (
            _decode_aarch64_ldr_w_unsigned(words[head_index])
            if head_index < len(words) else None
        )
        if (
            head_load is None or head_load[1] != bucket_address
            or head_load[2] != 0x20
        ):
            continue
        bucket_head = head_load[0]

        sentinel_index = skip_nops(head_index + 1)
        sentinel = (
            _decode_aarch64_subs_w_immediate(words[sentinel_index])
            if sentinel_index < len(words) else None
        )
        if sentinel is None or sentinel[1:] != (bucket_head, 1):
            continue
        entry_index_register = sentinel[0]

        empty_branch_index = skip_nops(sentinel_index + 1)
        empty_branch = (
            _decode_aarch64_conditional_branch_condition(words[empty_branch_index])
            if empty_branch_index < len(words) else None
        )
        if (
            empty_branch is None or empty_branch.get("kind") != "b_cond"
            or empty_branch.get("condition_code") != 4
        ):
            continue

        for base_index in range(empty_branch_index + 1, min(len(words), empty_branch_index + 65)):
            if is_scan_barrier(words[base_index]):
                break
            base_add = _decode_aarch64_add_imm64(words[base_index])
            if base_add is None or base_add[2] != 0x20:
                continue
            entries_base = base_add[0]

            stride_index, stride = find_after(
                base_index + 1,
                _decode_aarch64_movz_w_immediate,
                lambda item: item[1] == 12,
                limit=16,
            )
            if stride is None:
                continue
            stride_register = stride[0]

            # The next-index calculation occurs after an indirect call. Under
            # AAPCS64, only x19-x29 are guaranteed to survive that call. Without
            # stack spill/reload analysis, do not carry caller-saved values
            # across BLR and label the result as register-linked.
            if not all(
                19 <= register <= 29
                for register in (entry_index_register, stride_register, entries_base)
            ):
                continue

            multiply_index, multiply = find_after(
                stride_index + 1,
                _decode_aarch64_umaddl,
                lambda item: (
                    item[1] == entry_index_register
                    and item[2] == stride_register
                    and item[3] == 31
                ),
                limit=24,
            )
            if multiply is None:
                continue
            offset_register = multiply[0]

            entry_hash_index, entry_hash_load = find_after(
                multiply_index + 1,
                _decode_aarch64_ldr_w_register,
                lambda item: (
                    item[1] == entries_base and item[2] == offset_register
                ),
                limit=8,
            )
            if entry_hash_load is None:
                continue
            entry_hash_register = entry_hash_load[0]

            key_compare_index, key_compare = find_after(
                entry_hash_index + 1,
                _decode_aarch64_cmp_w_register,
                lambda item: item[0] == entry_hash_register
                or item[1] == entry_hash_register,
                limit=8,
            )
            if key_compare is None:
                continue
            hash_register = (
                key_compare[1]
                if key_compare[0] == entry_hash_register
                else key_compare[0]
            )
            # Recover only a contiguous, reachable MOV/NOP suffix immediately
            # before SDIV. Unknown instructions and control-flow boundaries stop
            # alias propagation instead of letting a stale earlier copy survive.
            alias_start = divide_index
            alias_limit = max(0, divide_index - 32)
            while alias_start > alias_limit:
                previous_word = words[alias_start - 1]
                if (
                    previous_word == 0xD503201F
                    or _decode_aarch64_mov_w_register(previous_word) is not None
                ):
                    alias_start -= 1
                else:
                    break

            hash_registers = {dividend}
            for index in range(alias_start, divide_index):
                if index not in reachable:
                    hash_registers = {dividend}
                    break
                previous_word = words[index]
                if previous_word == 0xD503201F:
                    continue
                move = _decode_aarch64_mov_w_register(previous_word)
                if move is None:
                    hash_registers = {dividend}
                    break
                destination, source = move
                aliases_before_move = set(hash_registers)
                if destination == dividend:
                    if source in aliases_before_move:
                        # The root register is rewritten from an existing alias;
                        # the hash value is unchanged.
                        hash_registers = aliases_before_move
                    else:
                        # The SDIV dividend itself now contains a different value.
                        hash_registers = {dividend}
                else:
                    hash_registers.discard(destination)
                    if source in aliases_before_move:
                        hash_registers.add(destination)
            if hash_register not in hash_registers:
                continue

            # The compare must still observe the SDIV hash value. Recognize every
            # GPR-writing instruction in this narrow interval; an unknown opcode
            # is a data-flow barrier, not permission to assume the register survives.
            def gpr_write_destination(instruction_word, instruction_pc):
                for decoder in (
                    _decode_aarch64_sdiv_w,
                    _decode_aarch64_msub_w,
                    _decode_aarch64_add_x_w_uxtw,
                    _decode_aarch64_ldr_w_unsigned,
                    _decode_aarch64_subs_w_immediate,
                    _decode_aarch64_movz_w_immediate,
                    _decode_aarch64_umaddl,
                    _decode_aarch64_ldr_w_register,
                    _decode_aarch64_mov_w_register,
                    _decode_aarch64_ldr_x_unsigned,
                    _decode_aarch64_add_imm64,
                ):
                    decoded = decoder(instruction_word)
                    if decoded is not None:
                        return decoded[0]
                if (
                    instruction_word == 0xD503201F
                    or _decode_aarch64_cmp_w_register(instruction_word) is not None
                    or _decode_aarch64_conditional_branch(
                        instruction_word, instruction_pc
                    ) is not None
                ):
                    return -1
                return None

            hash_value_survives = True
            for index in range(divide_index + 1, key_compare_index):
                destination = gpr_write_destination(words[index], index * 4)
                if destination is None or destination == hash_register:
                    hash_value_survives = False
                    break
            if not hash_value_survives:
                continue

            entry_index_registers = {entry_index_register}
            for index in range(multiply_index + 1, key_compare_index):
                move = _decode_aarch64_mov_w_register(words[index])
                if move is not None and move[1] in entry_index_registers:
                    entry_index_registers.add(move[0])

            unequal_branch_index = skip_nops(key_compare_index + 1)
            unequal_branch = (
                _decode_aarch64_conditional_branch_condition(words[unequal_branch_index])
                if unequal_branch_index < len(words) else None
            )
            if (
                unequal_branch is None or unequal_branch.get("kind") != "b_cond"
                or unequal_branch.get("condition_code") != 1
            ):
                continue

            entry_address_index, entry_address = find_after(
                unequal_branch_index + 1,
                _decode_aarch64_umaddl,
                lambda item: (
                    item[1] in entry_index_registers
                    and item[2] == stride_register
                    and item[3] == entries_base
                ),
                limit=12,
            )
            if entry_address is None:
                continue
            entry_address_register = entry_address[0]

            value_index, value_load = find_after(
                entry_address_index + 1,
                _decode_aarch64_ldr_w_unsigned,
                lambda item: (
                    item[1] == entry_address_register and item[2] == 8
                ),
                limit=12,
            )
            if value_load is None:
                continue

            comparer_index = None
            for index in range(value_index + 1, min(len(words), value_index + 64)):
                if _decode_aarch64_blr_register(words[index]) is not None:
                    comparer_index = index
                    break
                if is_scan_barrier(words[index]):
                    break
            if comparer_index is None:
                continue

            # Do not scan through arbitrary instructions after BLR: they may
            # overwrite even callee-saved values in the caller. Permit only NOPs
            # before the exact next-address calculation and its next-index load.
            next_address_index = skip_nops(comparer_index + 1)
            if next_address_index >= len(words):
                continue
            next_address = _decode_aarch64_umaddl(words[next_address_index])
            if (
                next_address is None
                or next_address[1] != entry_index_register
                or next_address[2] != stride_register
                or next_address[3] != entries_base
                or next_address[0] in {
                    entry_index_register, stride_register, entries_base,
                }
            ):
                continue

            next_index = skip_nops(next_address_index + 1)
            next_load = (
                _decode_aarch64_ldr_w_unsigned(words[next_index])
                if next_index < len(words) else None
            )
            if (
                next_load is None or next_load[1] != next_address[0]
                or next_load[2] != 4
            ):
                continue
            next_register = next_load[0]

            loop_compare_index = None
            for candidate in range(stride_index + 1, multiply_index):
                loop_compare = _decode_aarch64_cmp_w_register(words[candidate])
                if loop_compare is None or entry_index_register not in loop_compare:
                    continue
                loop_branch_index = skip_nops(candidate + 1)
                loop_branch = (
                    _decode_aarch64_conditional_branch_condition(words[loop_branch_index])
                    if loop_branch_index < len(words) else None
                )
                if (
                    loop_branch is not None
                    and loop_branch.get("kind") == "b_cond"
                    and loop_branch.get("condition_code") == 2
                ):
                    loop_compare_index = candidate
                    break
            if loop_compare_index is None:
                continue

            chain_branch_index = skip_nops(next_index + 1)
            chain_branch = (
                _decode_aarch64_conditional_branch_condition(words[chain_branch_index])
                if chain_branch_index < len(words) else None
            )
            if chain_branch is None:
                continue
            immediate = (words[chain_branch_index] >> 5) & 0x3FFF
            if immediate & 0x2000:
                immediate -= 0x4000
            target_index = chain_branch_index + immediate
            if (
                chain_branch.get("kind") != "tbz_tbnz"
                or chain_branch.get("register_index") != next_register
                or chain_branch.get("bit_index") != 31
                or chain_branch.get("predicate") != "zero"
                or target_index != loop_compare_index
            ):
                continue

            return {
                "status": "bucketed_membership_lookup_shape_candidate",
                "hash_modulo_bucket_index": True,
                "bucket_head_sentinel_check": True,
                "entry_stride_bytes": 12,
                "entry_hash_comparison": True,
                "indirect_comparer_dispatch": True,
                "entry_next_index_traversal": True,
                "entry_value_offset_bytes": 8,
                "entry_next_index_offset_bytes": 4,
                "post_comparer_live_inputs_call_preserved": True,
                "entry_chain_branch_targets_loop_compare": True,
                "managed_method_identity_verified": False,
                "managed_collection_owner_verified": False,
            }

    return unresolved

def _summarize_receiver_integer_lookup(
    receiver_code, receiver_start_va, networksettings_cctor_code,
    networksettings_cctor_start_va, deserialize_int_targets,
    known_method_targets, field_candidate, *,
    receiver_window_truncated=False,
    networksettings_cctor_window_truncated=False,
):
    """Trace a receive-key lookup only through reachable bounded CFG paths."""
    if type(receiver_code) is not bytes or len(receiver_code) % 4:
        raise ValueError("receiver code must be aligned AArch64 bytes")
    if type(networksettings_cctor_code) is not bytes or len(networksettings_cctor_code) % 4:
        raise ValueError("NetworkSettings cctor code must be aligned AArch64 bytes")
    if (
        type(receiver_start_va) is not int or receiver_start_va < 0
        or receiver_start_va % 4
    ):
        raise ValueError("receiver start must be aligned")
    if (
        type(networksettings_cctor_start_va) is not int
        or networksettings_cctor_start_va < 0
        or networksettings_cctor_start_va % 4
    ):
        raise ValueError("NetworkSettings cctor start must be aligned")
    if (
        type(deserialize_int_targets) is not set or not deserialize_int_targets
        or any(type(target) is not int or target < 0 or target % 4 for target in deserialize_int_targets)
    ):
        raise ValueError("deserialize targets must be aligned integer addresses")
    if (
        type(known_method_targets) is not set
        or any(type(target) is not int or target < 0 or target % 4 for target in known_method_targets)
    ):
        raise ValueError("known method targets must be an aligned integer set")
    if (
        type(receiver_window_truncated) is not bool
        or type(networksettings_cctor_window_truncated) is not bool
    ):
        raise ValueError("entry-window truncation flags must be built-in booleans")
    if receiver_window_truncated or networksettings_cctor_window_truncated:
        return {
            "status": "unresolved_truncated_entry_window",
            "receiver_entry_window_truncated": receiver_window_truncated,
            "networksettings_cctor_entry_window_truncated": (
                networksettings_cctor_window_truncated
            ),
            "wire_message_id_verified": False,
            "compression_behavior_verified": False,
            "wire_contract_verified": False,
            "apk_compatible": False,
        }, None

    class_cells = _networksettings_static_first_slot_store_cells(
        networksettings_cctor_code, networksettings_cctor_start_va
    )
    if len(class_cells) != 1:
        return {"status": "unresolved_networksettings_static_slot"}, None
    class_cell = next(iter(class_cells))

    words = [
        (receiver_start_va + offset, struct.unpack_from("<I", receiver_code, offset)[0])
        for offset in range(0, len(receiver_code), 4)
    ]
    reachable = _reachable_aarch64_instruction_indices(
        receiver_code, receiver_start_va
    )
    all_deserialize_calls = [
        index for index, (pc, word) in enumerate(words)
        if _decode_aarch64_bl_target(word, pc) in deserialize_int_targets
    ]
    deserialize_calls = [
        index for index in all_deserialize_calls if index in reachable
    ]
    call_counts = {
        "deserialize_int_call_count": len(deserialize_calls),
        "total_deserialize_int_call_count": len(all_deserialize_calls),
        "unreachable_deserialize_int_call_count": (
            len(all_deserialize_calls) - len(deserialize_calls)
        ),
    }
    if len(deserialize_calls) != 2:
        return {
            "status": "unresolved_deserialize_call_count",
            **call_counts,
        }, None

    first_call, second_call = deserialize_calls
    if not _aarch64_instruction_reaches(
        receiver_code, receiver_start_va, first_call, second_call
    ):
        return {
            "status": "unresolved_deserialize_call_path",
            **call_counts,
        }, None

    copy_index = _skip_aarch64_nops(words, second_call + 1)
    if (
        copy_index >= len(words) or copy_index not in reachable
        or not _aarch64_instruction_reaches(
            receiver_code, receiver_start_va, second_call, copy_index
        )
    ):
        return {
            "status": "unresolved_second_result_copy",
            **call_counts,
        }, None
    copy = _decode_aarch64_mov_w_register(words[copy_index][1])
    if copy is None or copy[1] != 0 or copy[0] == 0:
        return {
            "status": "unresolved_second_result_copy",
            **call_counts,
        }, None
    key_register = copy[0]

    sequences = _networksettings_static_first_slot_read_sequences(
        receiver_code, receiver_start_va, class_cell
    )
    ordered_sequences = [
        sequence for sequence in sequences
        if sequence["load_index"] in reachable
        and sequence["first_index"] in reachable
        and sequence["second_index"] in reachable
        and sequence["read_index"] in reachable
        and _skip_aarch64_nops(words, sequence["load_index"] + 1) == first_call
        and sequence["first_index"] == _skip_aarch64_nops(words, copy_index + 1)
        and _aarch64_instruction_reaches(
            receiver_code, receiver_start_va, copy_index, sequence["first_index"]
        )
    ]
    if not ordered_sequences:
        return {
            "status": "unresolved_networksettings_static_slot_read",
            **call_counts,
        }, None

    candidates = []
    saw_key_alias = False
    saw_key_argument = False
    for sequence in ordered_sequences:
        chain_registers = {
            sequence["class_register"], sequence["object_register"],
            sequence["static_fields_register"], sequence["value_register"],
        }
        if key_register in chain_registers:
            saw_key_alias = True
            continue

        argument_index = _skip_aarch64_nops(words, sequence["read_index"] + 1)
        if (
            argument_index >= len(words) or argument_index not in reachable
            or not _aarch64_instruction_reaches(
                receiver_code, receiver_start_va, sequence["read_index"], argument_index
            )
        ):
            continue
        argument = _decode_aarch64_mov_w_register(words[argument_index][1])
        if argument is None or argument[0] != 1 or argument[1] != key_register:
            continue
        saw_key_argument = True

        call_index = _skip_aarch64_nops(words, argument_index + 1)
        if (
            call_index >= len(words) or call_index not in reachable
            or not _aarch64_instruction_reaches(
                receiver_code, receiver_start_va, argument_index, call_index
            )
        ):
            continue
        lookup_target = _decode_aarch64_bl_target(
            words[call_index][1], words[call_index][0]
        )
        if lookup_target is None or lookup_target in deserialize_int_targets:
            continue
        candidates.append((lookup_target, sequence))

    if len(candidates) != 1:
        if saw_key_alias:
            status = "unresolved_key_register_alias"
        elif not saw_key_argument:
            status = "unresolved_key_argument"
        else:
            status = "unresolved_lookup_call"
        return {
            "status": status,
            **call_counts,
            "candidate_count": len(candidates),
        }, None

    target, _sequence = candidates[0]
    candidate_name = (
        field_candidate.get("name")
        if type(field_candidate) is dict else None
    )
    summary = {
        "status": "static_key_lookup_candidate",
        **call_counts,
        "source_call_ordinal": 2,
        "second_result_copied_from_w0": True,
        "key_forwarded_to_w1": True,
        "networksettings_static_first_slot_store_observed": True,
        "networksettings_static_first_slot_read_observed": True,
        "lookup_target_is_metadata_method": target in known_method_targets,
        "field_candidate_name": candidate_name,
        "field_candidate_leading_default_count": (
            field_candidate.get("leading_default_backed_field_count")
            if type(field_candidate) is dict else None
        ),
        "field_attribution_status": (
            "metadata_order_candidate_only" if candidate_name else "unresolved"
        ),
        "callee_fde_entry_resolved": False,
        "callee_entry_window_bytes": None,
        "callee_hash_bucket_opcode_families_present": False,
        "callee_bucketed_lookup_shape": {
            "status": "unresolved",
            "managed_method_identity_verified": False,
            "managed_collection_owner_verified": False,
        },
        "wire_message_id_verified": False,
        "compression_behavior_verified": False,
        "wire_contract_verified": False,
        "apk_compatible": False,
    }
    return summary, target

def _bounded_fde_code_for_target(elf, sections, target):
    """Return a private exact-FDE-entry window, or None when it cannot be bounded."""
    try:
        header_section = sections[".eh_frame_hdr"]
        frame_section = sections[".eh_frame"]
        header = _slice(
            elf, header_section["offset"], header_section["size"], ".eh_frame_hdr"
        )
        executable_ranges = tuple(
            (section["address"], section["address"] + section["size"])
            for section in sections.values()
            if section["type"] == 1 and (section["flags"] & 0x4)
        )
        entries = parse_eh_frame_header(
            header,
            header_section["address"],
            (
                frame_section["address"],
                frame_section["address"] + frame_section["size"],
            ),
            executable_ranges,
        )
        window = find_entry_window(entries, target)
        if window is None:
            return None
        matches = [
            section for section in sections.values()
            if section["type"] == 1 and (section["flags"] & 0x4)
            and section["address"] <= target < section["address"] + section["size"]
        ]
        if len(matches) != 1:
            return None
        section = matches[0]
        file_offset = section["offset"] + target - section["address"]
        code = _slice(elf, file_offset, window.size_bytes, "bounded native helper FDE window")
        return window.size_bytes, code
    except (EhFrameIndexError, KeyError, ValueError):
        return None


def _decode_aarch64_mov_x_register(word):
    """Decode the unshifted MOV Xd, Xm alias (ORR Xd, XZR, Xm, LSL #0)."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if ((word & 0xFFE0FC00) != 0xAA000000
            or (word & 0x3E0) != 0x3E0):
        return None
    return word & 0x1F, (word >> 16) & 0x1F


def _decode_aarch64_blr_register(word):
    """Return the BLR/BLRA target register, or None for another instruction."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFFFFFC1F) == 0xD63F0000:  # BLR Xn
        return (word >> 5) & 0x1F
    if (word & 0xFFFFFC00) in (0xD73F0800, 0xD73F0C00):  # BLRAA/BLRAB Xn, Xm
        return (word >> 5) & 0x1F
    if (word & 0xFFFFFC1F) in (0xD63F081F, 0xD63F0C1F):  # BLRAAZ/BLRABZ Xn
        return (word >> 5) & 0x1F
    return None


def _decode_aarch64_br_register(word):
    """Return the BR/BRA target register, or None for another instruction."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFFFFFC1F) == 0xD61F0000:  # BR Xn
        return (word >> 5) & 0x1F
    if (word & 0xFFFFFC00) in (0xD71F0800, 0xD71F0C00):  # BRAA/BRAB Xn, Xm
        return (word >> 5) & 0x1F
    if (word & 0xFFFFFC1F) in (0xD61F081F, 0xD61F0C1F):  # BRAAZ/BRABZ Xn
        return (word >> 5) & 0x1F
    return None


def _relocated_indirect_call_events(code, start_va, relocations, *, include_offsets=False):
    """Resolve bounded ADR/ADRP/ADD/LDR/MOV-X chains ending in BLR/PAuth calls or branches.

    Any unrecognized instruction clears the small abstract register state.
    This deliberately misses ordinary virtual calls and runtime-computed
    pointers rather than guessing their targets.
    """
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact built-in bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if type(relocations) is not dict:
        raise ValueError("relocations must be an exact built-in dict")
    if any(type(slot) is not int or slot < 0 for slot in relocations):
        raise ValueError("relocation slots must be non-negative built-in integers")

    registers = {}
    events = []
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset

        adr = _decode_aarch64_adr(word, pc)
        if adr is not None:
            destination, address = adr
            registers[destination] = address
            continue

        adrp = _decode_aarch64_adrp(word, pc)
        if adrp is not None:
            destination, page = adrp
            registers[destination] = page
            continue

        add = _decode_aarch64_add_imm64(word)
        if add is not None:
            destination, source, immediate = add
            if source in registers:
                registers[destination] = registers[source] + immediate
            else:
                registers.pop(destination, None)
            continue

        load = _decode_aarch64_ldr_x_unsigned(word)
        if load is not None:
            target_register, base_register, offset_bytes = load
            base = registers.get(base_register)
            relocation = relocations.get(base + offset_bytes) if base is not None else None
            if relocation is not None and (
                type(relocation) is not tuple
                or len(relocation) != 2
                or type(relocation[0]) is not int
                or type(relocation[1]) is not int
            ):
                raise ValueError(
                    "relocation entry must be an exact two-integer tuple"
                )
            if (
                relocation is not None
                and relocation[0] == R_AARCH64_RELATIVE
                and relocation[1] >= 0
            ):
                registers[target_register] = relocation[1]
            else:
                registers.pop(target_register, None)
            continue

        move = _decode_aarch64_mov_x_register(word)
        if move is not None:
            destination, source = move
            if destination != 31:
                if source == 31:
                    registers[destination] = 0
                elif source in registers:
                    registers[destination] = registers[source]
                else:
                    registers.pop(destination, None)
            continue

        call_register = _decode_aarch64_blr_register(word)
        if call_register is not None:
            target = registers.get(call_register)
            events.append((offset, "call", target) if include_offsets else ("call", target))
            registers.clear()
            continue

        tail_register = _decode_aarch64_br_register(word)
        if tail_register is not None:
            target = registers.get(tail_register)
            events.append((offset, "tail", target) if include_offsets else ("tail", target))
            registers.clear()
            continue

        if word != 0xD503201F:
            registers.clear()
    return events


def _relocated_indirect_call_targets(code, start_va, relocations):
    """Return internal candidate targets; callers must not publish raw addresses."""
    return {
        target
        for _kind, target in _relocated_indirect_call_events(
            code, start_va, relocations
        )
        if target is not None
    }


def _summarize_relocated_indirect_calls(code, start_va, relocations, method_targets):
    """Resolve indirect calls and preserve order among uniquely resolved labels.

    The sequence is only for relocation-backed indirect events in this bounded
    linear window. It omits unresolved/ambiguous events and is not interleaved
    with direct BL calls or a control-flow execution trace.
    """
    calls = Counter()
    tails = Counter()
    call_sequence = []
    tail_sequence = []
    unresolved_calls = 0
    unresolved_tails = 0
    ambiguous_calls = 0
    ambiguous_tails = 0
    for kind, target in _relocated_indirect_call_events(code, start_va, relocations):
        labels = method_targets.get(target, ()) if target is not None else ()
        if len(labels) == 1:
            label = labels[0]
            if kind == "call":
                calls[label] += 1
                call_sequence.append(label)
            else:
                tails[label] += 1
                tail_sequence.append(label)
        elif len(labels) > 1:
            if kind == "call":
                ambiguous_calls += 1
            else:
                ambiguous_tails += 1
        elif kind == "call":
            unresolved_calls += 1
        else:
            unresolved_tails += 1
    return {
        "resolved_indirect_method_call_counts": dict(sorted(calls.items())),
        "resolved_indirect_method_call_sequence": call_sequence,
        "resolved_indirect_tail_method_call_counts": dict(sorted(tails.items())),
        "resolved_indirect_tail_method_call_sequence": tail_sequence,
        "unresolved_indirect_call_count": unresolved_calls,
        "unresolved_indirect_tail_call_count": unresolved_tails,
        "ambiguous_indirect_call_count": ambiguous_calls,
        "ambiguous_indirect_tail_call_count": ambiguous_tails,
    }


def _summarize_ordered_serializer_helper_calls(code, start_va, relocations, helper_targets):
    """Interleave uniquely resolved direct and relocation-backed helper callsites.

    The result is a linear address-order observation inside one bounded method
    window, not an execution trace: branches, loops and mutually exclusive
    paths are not evaluated.
    """
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact built-in bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if type(relocations) is not dict or type(helper_targets) is not dict:
        raise ValueError("relocations and helper targets must be exact built-in dicts")
    if any(type(slot) is not int or slot < 0 for slot in relocations):
        raise ValueError("relocation slots must be non-negative built-in integers")
    for target, labels in helper_targets.items():
        if type(target) is not int or target < 0 or target % 4:
            raise ValueError(
                "helper targets must be non-negative aligned built-in integers"
            )
        if (
            type(labels) not in (list, tuple)
            or not labels
            or any(type(label) is not str or not label for label in labels)
        ):
            raise ValueError(
                "helper target labels must be non-empty built-in string lists or tuples"
            )

    indirect_by_offset = {
        offset: (kind, target)
        for offset, kind, target in _relocated_indirect_call_events(
            code, start_va, relocations, include_offsets=True
        )
    }
    sequence = []
    counts = Counter()
    ambiguous_direct = 0
    ambiguous_indirect = 0
    indirect_not_resolved_as_helper = 0

    def append_resolved(kind, label):
        sequence.append({"kind": kind, "method": label})
        counts[label] += 1

    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset

        direct_target = _decode_aarch64_bl_target(word, pc)
        if direct_target is not None:
            labels = helper_targets.get(direct_target, ())
            if len(labels) == 1:
                append_resolved("direct_call", labels[0])
            elif len(labels) > 1:
                sequence.append({
                    "kind": "direct_call",
                    "resolution": "ambiguous_serializer_helper",
                })
                ambiguous_direct += 1
            continue

        tail_target = _decode_aarch64_b_target(word, pc)
        if tail_target is not None:
            labels = helper_targets.get(tail_target, ())
            if len(labels) == 1:
                append_resolved("direct_tail_call", labels[0])
            elif len(labels) > 1:
                sequence.append({
                    "kind": "direct_tail_call",
                    "resolution": "ambiguous_serializer_helper",
                })
                ambiguous_direct += 1
            continue

        indirect = indirect_by_offset.get(offset)
        if indirect is None:
            continue
        indirect_kind, target = indirect
        call_kind = "indirect_call" if indirect_kind == "call" else "indirect_tail_call"
        labels = helper_targets.get(target, ()) if target is not None else ()
        if len(labels) == 1:
            append_resolved(call_kind, labels[0])
        elif len(labels) > 1:
            sequence.append({
                "kind": call_kind,
                "resolution": "ambiguous_serializer_helper",
            })
            ambiguous_indirect += 1
        else:
            sequence.append({
                "kind": call_kind,
                "resolution": "not_resolved_as_serializer_helper",
            })
            indirect_not_resolved_as_helper += 1

    return {
        "linear_helper_callsite_order": sequence,
        "linear_helper_callsite_counts": dict(sorted(counts.items())),
        "ambiguous_direct_helper_callsite_count": ambiguous_direct,
        "ambiguous_indirect_helper_callsite_count": ambiguous_indirect,
        "indirect_callsite_not_resolved_as_helper_count": indirect_not_resolved_as_helper,
    }




def _decode_aarch64_conditional_branch(word, pc):
    """Decode B.cond, CBZ/CBNZ or TBZ/TBNZ into (kind, target)."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None

    if (word & 0xFF000010) == 0x54000000:  # B.cond, signed imm19
        immediate = (word >> 5) & 0x7FFFF
        bits = 19
        kind = "b_cond"
    elif (word & 0x7E000000) == 0x34000000:  # CBZ/CBNZ, signed imm19
        immediate = (word >> 5) & 0x7FFFF
        bits = 19
        kind = "cbz_cbnz"
    elif (word & 0x7E000000) == 0x36000000:  # TBZ/TBNZ, signed imm14
        immediate = (word >> 5) & 0x3FFF
        bits = 14
        kind = "tbz_tbnz"
    else:
        return None

    sign = 1 << (bits - 1)
    immediate = (immediate ^ sign) - sign
    return kind, pc + (immediate << 2)



_AARCH64_CONDITION_NAMES = (
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
)


def _decode_aarch64_conditional_branch_condition(word):
    """Decode the predicate operands of B.cond, CBZ/CBNZ or TBZ/TBNZ.

    This reports instruction encoding only. It does not evaluate flags or
    register values and does not infer a runtime-selected edge.
    """
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None

    if (word & 0xFF000010) == 0x54000000:  # B.cond
        condition_code = word & 0xF
        return {
            "kind": "b_cond",
            "condition_code": condition_code,
            "condition_name": _AARCH64_CONDITION_NAMES[condition_code],
        }

    if (word & 0x7E000000) == 0x34000000:  # CBZ/CBNZ
        return {
            "kind": "cbz_cbnz",
            "register_index": word & 0x1F,
            "register_width_bits": 64 if word & (1 << 31) else 32,
            "predicate": "nonzero" if word & (1 << 24) else "zero",
        }

    if (word & 0x7E000000) == 0x36000000:  # TBZ/TBNZ
        bit_index = (((word >> 31) & 1) << 5) | ((word >> 19) & 0x1F)
        return {
            "kind": "tbz_tbnz",
            "register_index": word & 0x1F,
            "bit_index": bit_index,
            "predicate": "nonzero" if word & (1 << 24) else "zero",
        }

    return None


def _decode_aarch64_flag_setting_producer(word):
    """Decode a narrow, adjacent AArch64 NZCV producer without evaluating flags.

    Only ADDS/SUBS immediate and shifted-register forms are recognized. The
    caller must separately establish that no non-NOP instruction intervenes
    before B.cond. Numeric immediates are reduced to coarse classes.
    """
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None

    width_bits = 64 if word & (1 << 31) else 32
    subtract = bool(word & (1 << 30))
    sets_flags = bool(word & (1 << 29))
    if not sets_flags:
        return None

    destination = word & 0x1F
    source = (word >> 5) & 0x1F

    # ADD/SUB (immediate): fixed opcode bits 28..23, with bit 23 reserved 0.
    if (word & 0x1F800000) == 0x11000000:
        immediate = (word >> 10) & 0xFFF
        shifted = bool(word & (1 << 22))
        effective_is_zero = immediate == 0
        operation = (
            ("cmp" if subtract else "cmn") if destination == 31
            else ("subs" if subtract else "adds")
        )
        return {
            "kind": operation + "_immediate",
            "width_bits": width_bits,
            "source_register_index": source,
            "source_register_31_role": (
                "stack_pointer" if source == 31 else "general_register"
            ),
            "destination_is_zero": destination == 31,
            "immediate_class": (
                "zero" if effective_is_zero else
                "nonzero_shifted_12bit" if shifted else
                "nonzero_12bit"
            ),
        }

    # ADD/SUB (shifted register). ROR is reserved for this instruction family.
    if (word & 0x1F200000) == 0x0B000000:
        shift_code = (word >> 22) & 0x3
        shift_amount = (word >> 10) & 0x3F
        if shift_code == 3 or shift_amount >= width_bits:
            return None
        right = (word >> 16) & 0x1F
        shift_name = ("lsl", "lsr", "asr")[shift_code]
        operation = (
            ("cmp" if subtract else "cmn") if destination == 31
            else ("subs" if subtract else "adds")
        )
        return {
            "kind": operation + "_shifted_register",
            "width_bits": width_bits,
            "left_register_index": source,
            "left_register_31_role": (
                "zero_register" if source == 31 else "general_register"
            ),
            "right_register_index": right,
            "right_register_31_role": (
                "zero_register" if right == 31 else "general_register"
            ),
            "destination_is_zero": destination == 31,
            "shift_kind": shift_name,
            "shift_amount": shift_amount,
        }

    return None


def _find_adjacent_aarch64_flag_producer(code, block_start, branch_index):
    """Find a supported NZCV producer immediately before B.cond, skipping NOPs."""
    index = branch_index - 1
    nop_count = 0
    while index >= block_start:
        word = struct.unpack_from("<I", code, index * 4)[0]
        if word == 0xD503201F:
            nop_count += 1
            index -= 1
            continue
        producer = _decode_aarch64_flag_setting_producer(word)
        if producer is None:
            return None
        return {
            **producer,
            "instruction_index": index,
            "intervening_nop_count": nop_count,
        }
    return None


def _validate_control_flow_flag_producer(producer):
    """Validate a redacted, bounded NZCV-producer record."""
    if type(producer) is not dict or any(type(key) is not str for key in producer):
        raise ValueError("conditional branch flag producer must be a built-in dict")
    kind = producer.get("kind")
    if type(kind) is not str:
        raise ValueError("conditional branch flag producer kind is invalid")

    width = producer.get("width_bits")
    destination_is_zero = producer.get("destination_is_zero")
    instruction_index = producer.get("instruction_index")
    nop_count = producer.get("intervening_nop_count")
    compare_alias = kind.startswith(("cmp_", "cmn_"))
    if (
        type(width) is not int or width not in (32, 64)
        or type(destination_is_zero) is not bool
        or destination_is_zero != compare_alias
        or type(instruction_index) is not int or instruction_index < 0
        or type(nop_count) is not int or not 0 <= nop_count <= 16383
    ):
        raise ValueError("conditional branch flag producer metadata is invalid")

    common = {
        "kind", "width_bits", "destination_is_zero",
        "instruction_index", "intervening_nop_count",
    }
    if kind in {"cmp_immediate", "cmn_immediate", "adds_immediate", "subs_immediate"}:
        expected = common | {
            "source_register_index", "source_register_31_role", "immediate_class",
        }
        if set(producer) != expected:
            raise ValueError("immediate flag producer fields are invalid")
        source = producer.get("source_register_index")
        role = producer.get("source_register_31_role")
        immediate_class = producer.get("immediate_class")
        if (
            type(source) is not int or not 0 <= source <= 31
            or type(role) is not str
            or role != ("stack_pointer" if source == 31 else "general_register")
            or type(immediate_class) is not str
            or immediate_class not in {
                "zero", "nonzero_12bit", "nonzero_shifted_12bit",
            }
        ):
            raise ValueError("immediate flag producer operands are invalid")
    elif kind in {
        "cmp_shifted_register", "cmn_shifted_register",
        "adds_shifted_register", "subs_shifted_register",
    }:
        expected = common | {
            "left_register_index", "left_register_31_role",
            "right_register_index", "right_register_31_role",
            "shift_kind", "shift_amount",
        }
        if set(producer) != expected:
            raise ValueError("shifted-register flag producer fields are invalid")
        left = producer.get("left_register_index")
        right = producer.get("right_register_index")
        if (
            type(left) is not int or not 0 <= left <= 31
            or type(producer.get("left_register_31_role")) is not str
            or producer["left_register_31_role"] != (
                "zero_register" if left == 31 else "general_register"
            )
            or type(right) is not int or not 0 <= right <= 31
            or type(producer.get("right_register_31_role")) is not str
            or producer["right_register_31_role"] != (
                "zero_register" if right == 31 else "general_register"
            )
            or type(producer.get("shift_kind")) is not str
            or producer["shift_kind"] not in {"lsl", "lsr", "asr"}
            or type(producer.get("shift_amount")) is not int
            or not 0 <= producer["shift_amount"] < width
        ):
            raise ValueError("shifted-register flag producer operands are invalid")
    else:
        raise ValueError("conditional branch flag producer kind is invalid")
    return dict(producer)


def _validate_control_flow_branch_condition(condition):
    """Validate a redacted conditional-branch predicate object."""
    if type(condition) is not dict or any(type(key) is not str for key in condition):
        raise ValueError("conditional branch predicate must be a built-in dict")
    kind = condition.get("kind")
    if kind == "b_cond":
        if set(condition) != {"kind", "condition_code", "condition_name"}:
            raise ValueError("B.cond predicate fields are invalid")
        code = condition.get("condition_code")
        name = condition.get("condition_name")
        if (
            type(code) is not int or not 0 <= code < len(_AARCH64_CONDITION_NAMES)
            or type(name) is not str or name != _AARCH64_CONDITION_NAMES[code]
        ):
            raise ValueError("B.cond predicate encoding is invalid")
    elif kind == "cbz_cbnz":
        if set(condition) != {
            "kind", "register_index", "register_width_bits", "predicate"
        }:
            raise ValueError("CBZ/CBNZ predicate fields are invalid")
        if (
            type(condition.get("register_index")) is not int
            or not 0 <= condition["register_index"] <= 31
            or type(condition.get("register_width_bits")) is not int
            or condition["register_width_bits"] not in (32, 64)
            or type(condition.get("predicate")) is not str
            or condition["predicate"] not in ("zero", "nonzero")
        ):
            raise ValueError("CBZ/CBNZ predicate encoding is invalid")
    elif kind == "tbz_tbnz":
        if set(condition) != {
            "kind", "register_index", "bit_index", "predicate"
        }:
            raise ValueError("TBZ/TBNZ predicate fields are invalid")
        if (
            type(condition.get("register_index")) is not int
            or not 0 <= condition["register_index"] <= 31
            or type(condition.get("bit_index")) is not int
            or not 0 <= condition["bit_index"] <= 63
            or type(condition.get("predicate")) is not str
            or condition["predicate"] not in ("zero", "nonzero")
        ):
            raise ValueError("TBZ/TBNZ predicate encoding is invalid")
    else:
        raise ValueError("conditional branch predicate kind is invalid")
    return dict(condition)


def _is_aarch64_return(word):
    """Recognize RET Xn, including RET X30, without interpreting its target."""
    return (
        type(word) is int
        and 0 <= word <= 0xFFFFFFFF
        and (word & 0xFFFFFC1F) == 0xD65F0000
    )


def _summarize_control_flow_serializer_helper_blocks(
    code, start_va, relocations, helper_targets, *, method_targets=None
):
    """Group helper callsites by reachable intraprocedural basic block.

    This is a bounded static CFG summary, not symbolic execution. Conditional
    edges are both considered possible; branches leaving the method window are
    exits. No native addresses or instruction words are emitted.
    """
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact built-in bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if type(relocations) is not dict or type(helper_targets) is not dict:
        raise ValueError("relocations and helper targets must be exact built-in dicts")
    if method_targets is not None and type(method_targets) is not dict:
        raise ValueError("method targets must be an exact built-in dict")

    def validate_target_labels(mapping, label):
        for target, labels in mapping.items():
            if type(target) is not int or target < 0 or target % 4:
                raise ValueError(
                    f"{label} targets must be non-negative aligned built-in integers"
                )
            if (
                type(labels) not in (list, tuple)
                or any(type(item) is not str or not item for item in labels)
            ):
                raise ValueError(
                    f"{label} labels must be non-empty built-in string lists or tuples"
                )

    validate_target_labels(helper_targets, "helper target")
    if method_targets is not None:
        validate_target_labels(method_targets, "method target")

    instruction_count = len(code) // 4
    if instruction_count == 0:
        return {
            "control_flow_analysis_kind": "bounded_intraprocedural_basic_blocks",
            "control_flow_instruction_count": 0,
            "control_flow_block_count": 0,
            "control_flow_basic_blocks": [],
            "control_flow_basic_blocks_truncated": False,
            "control_flow_reachable_callsite_observation_count": 0,
            "control_flow_unreachable_callsite_observation_count": 0,
            "control_flow_reachable_resolved_helper_callsite_count": 0,
            "control_flow_unreachable_resolved_helper_callsite_count": 0,
            "control_flow_reachable_resolved_metadata_method_callsite_count": 0,
            "control_flow_unreachable_resolved_metadata_method_callsite_count": 0,
            "control_flow_conditional_branch_count": 0,
            "control_flow_external_branch_exit_count": 0,
        }

    window_end = start_va + len(code)
    indirect_by_offset = {
        offset: (kind, target)
        for offset, kind, target in _relocated_indirect_call_events(
            code, start_va, relocations, include_offsets=True
        )
    }
    branch_at = {}
    calls_at = defaultdict(list)
    conditional_count = 0
    external_exit_count = 0

    def in_window(target):
        return (
            type(target) is int
            and start_va <= target < window_end
            and (target - start_va) % 4 == 0
        )

    def target_index(target):
        return (target - start_va) // 4 if in_window(target) else None

    def helper_event(kind, target, *, include_unresolved):
        labels = helper_targets.get(target, ()) if target is not None else ()
        if len(labels) == 1:
            return {"kind": kind, "method": labels[0]}
        if len(labels) > 1:
            return {"kind": kind, "resolution": "ambiguous_serializer_helper"}

        if method_targets is not None and target is not None:
            method_labels = method_targets.get(target, ())
            if len(method_labels) == 1:
                return {
                    "kind": kind,
                    "method": method_labels[0],
                    "target_kind": "metadata_method",
                }
            if len(method_labels) > 1:
                return {"kind": kind, "resolution": "ambiguous_metadata_method"}

        if include_unresolved:
            return {
                "kind": kind,
                "resolution": (
                    "not_resolved_as_metadata_method_or_serializer_helper"
                    if method_targets is not None
                    else "not_resolved_as_serializer_helper"
                ),
            }
        return None

    for index in range(instruction_count):
        offset = index * 4
        pc = start_va + offset
        word = struct.unpack_from("<I", code, offset)[0]

        direct_call_target = _decode_aarch64_bl_target(word, pc)
        if direct_call_target is not None:
            event = helper_event(
                "direct_call", direct_call_target, include_unresolved=False
            )
            if event is not None:
                calls_at[index].append(event)
            continue

        conditional = _decode_aarch64_conditional_branch(word, pc)
        if conditional is not None:
            kind, target = conditional
            target_slot = target_index(target)
            if target_slot is None:
                external_exit_count += 1
            branch_at[index] = {
                "kind": kind,
                "conditional": True,
                "target_index": target_slot,
                "condition": _decode_aarch64_conditional_branch_condition(word),
            }
            conditional_count += 1
            continue

        direct_branch_target = _decode_aarch64_b_target(word, pc)
        if direct_branch_target is not None:
            target_slot = target_index(direct_branch_target)
            if target_slot is None:
                event = helper_event(
                    "direct_tail_call",
                    direct_branch_target,
                    include_unresolved=False,
                )
                if event is not None:
                    calls_at[index].append(event)
                else:
                    external_exit_count += 1
            branch_at[index] = {
                "kind": "b",
                "conditional": False,
                "target_index": target_slot,
            }
            continue

        indirect = indirect_by_offset.get(offset)
        if indirect is not None:
            indirect_kind, target = indirect
            if indirect_kind == "call":
                # Resolve BLR targets after CFG construction so branch-local
                # register state cannot leak through a linear scan.
                continue

            target_slot = target_index(target)
            if target_slot is not None:
                branch_at[index] = {
                    "kind": "indirect_branch",
                    "conditional": False,
                    "target_index": target_slot,
                }
            else:
                calls_at[index].append(
                    helper_event(
                        "indirect_tail_call", target, include_unresolved=True
                    )
                )
                branch_at[index] = {
                    "kind": "indirect_tail",
                    "conditional": False,
                    "target_index": None,
                }
                external_exit_count += 1
            continue

        if _decode_aarch64_br_register(word) is not None:
            branch_at[index] = {
                "kind": "indirect_branch_unresolved",
                "conditional": False,
                "target_index": None,
            }
            external_exit_count += 1
            continue

        if _is_aarch64_return(word):
            branch_at[index] = {
                "kind": "return",
                "conditional": False,
                "target_index": None,
            }

    starts = {0}
    for index, branch in branch_at.items():
        if index + 1 < instruction_count:
            starts.add(index + 1)
        target_slot = branch["target_index"]
        if target_slot is not None:
            starts.add(target_slot)

    ordered_starts = sorted(starts)
    blocks = []
    block_for_instruction = {}
    for block_index, block_start in enumerate(ordered_starts):
        block_end = (
            ordered_starts[block_index + 1]
            if block_index + 1 < len(ordered_starts)
            else instruction_count
        )
        block = {
            "block_index": block_index,
            "instruction_start": block_start,
            "instruction_count": block_end - block_start,
            "successors": [],
        }
        blocks.append(block)
        for instruction_index in range(block_start, block_end):
            block_for_instruction[instruction_index] = block_index

    for block in blocks:
        block_end = block["instruction_start"] + block["instruction_count"]
        terminator = branch_at.get(block_end - 1)
        successors = []
        successor_edges = []
        if terminator is None:
            if block_end < instruction_count:
                target_block = block_for_instruction[block_end]
                successors.append(target_block)
                successor_edges.append({
                    "target_block": target_block,
                    "kind": "fallthrough",
                })
        elif terminator["conditional"]:
            target_slot = terminator["target_index"]
            if target_slot is not None:
                target_block = block_for_instruction[target_slot]
                successors.append(target_block)
                successor_edges.append({
                    "target_block": target_block,
                    "kind": "conditional_taken",
                })
            if block_end < instruction_count:
                target_block = block_for_instruction[block_end]
                successors.append(target_block)
                successor_edges.append({
                    "target_block": target_block,
                    "kind": "conditional_fallthrough",
                })
        else:
            target_slot = terminator["target_index"]
            if target_slot is not None:
                target_block = block_for_instruction[target_slot]
                successors.append(target_block)
                successor_edges.append({
                    "target_block": target_block,
                    "kind": "branch_target",
                })
        block["successors"] = sorted(set(successors))
        # Keep edge semantics separately from the deduplicated successor set.
        # A conditional target may equal its fallthrough block; both outcomes
        # remain observable even though they share one destination block.
        block["successor_edges"] = successor_edges
        block["terminator"] = (
            None if terminator is None else terminator["kind"]
        )
        if terminator is not None and terminator["conditional"]:
            condition = terminator.get("condition")
            if condition is not None:
                block["terminator_condition"] = dict(condition)
                if condition.get("kind") == "b_cond":
                    flag_producer = _find_adjacent_aarch64_flag_producer(
                        code, block["instruction_start"], block_end - 1
                    )
                    if flag_producer is not None:
                        block["terminator_flag_producer"] = flag_producer
        block["external_branch_exit"] = bool(
            terminator is not None
            and terminator["conditional"]
            and terminator["target_index"] is None
        )
        block["external_fallthrough_exit"] = bool(
            terminator is not None
            and terminator["conditional"]
            and block_end == instruction_count
        )

    reachable = set()
    pending = [0]
    while pending:
        block_index = pending.pop()
        if block_index in reachable:
            continue
        reachable.add(block_index)
        pending.extend(
            successor for successor in blocks[block_index]["successors"]
            if successor not in reachable
        )

    # Resolve BLR targets with the same bounded CFG used for the block report.
    # State crosses only one reachable forward predecessor; joins and backedges
    # deliberately lose it rather than merging potentially different pointers.
    predecessors = [set() for _ in blocks]
    for source, block in enumerate(blocks):
        for destination in block["successors"]:
            predecessors[destination].add(source)

    outgoing_states = {}
    for block in blocks:
        block_index = block["block_index"]
        block_start = block["instruction_start"]
        block_end = block_start + block["instruction_count"]

        if block_index not in reachable:
            registers = {}
        else:
            incoming = predecessors[block_index] & reachable
            if block_index == 0 or len(incoming) != 1:
                registers = {}
            else:
                predecessor = next(iter(incoming))
                if (
                    predecessor < block_index
                    and blocks[predecessor]["instruction_start"] < block_start
                    and predecessor in outgoing_states
                ):
                    registers = dict(outgoing_states[predecessor])
                else:
                    registers = {}

        for instruction_index in range(block_start, block_end):
            word = struct.unpack_from("<I", code, instruction_index * 4)[0]
            pc = start_va + instruction_index * 4

            adr = _decode_aarch64_adr(word, pc)
            if adr is not None:
                destination, address = adr
                registers[destination] = address
                continue

            adrp = _decode_aarch64_adrp(word, pc)
            if adrp is not None:
                destination, page = adrp
                registers[destination] = page
                continue

            add = _decode_aarch64_add_imm64(word)
            if add is not None:
                destination, source, immediate = add
                if source in registers:
                    registers[destination] = registers[source] + immediate
                else:
                    registers.pop(destination, None)
                continue

            load = _decode_aarch64_ldr_x_unsigned(word)
            if load is not None:
                target_register, base_register, offset_bytes = load
                base = registers.get(base_register)
                relocation = (
                    relocations.get(base + offset_bytes)
                    if base is not None else None
                )
                if (
                    isinstance(relocation, tuple)
                    and len(relocation) == 2
                    and relocation[0] == R_AARCH64_RELATIVE
                    and type(relocation[1]) is int
                    and relocation[1] >= 0
                ):
                    registers[target_register] = relocation[1]
                else:
                    registers.pop(target_register, None)
                continue

            move = _decode_aarch64_mov_x_register(word)
            if move is not None:
                destination, source = move
                if destination != 31:
                    if source == 31:
                        registers[destination] = 0
                    elif source in registers:
                        registers[destination] = registers[source]
                    else:
                        registers.pop(destination, None)
                continue

            call_register = _decode_aarch64_blr_register(word)
            if call_register is not None:
                calls_at[instruction_index].append(
                    helper_event(
                        "indirect_call",
                        registers.get(call_register),
                        include_unresolved=True,
                    )
                )
                registers.clear()
                continue

            if _decode_aarch64_bl_target(word, pc) is not None:
                registers.clear()
                continue

            if (
                _decode_aarch64_conditional_branch(word, pc) is not None
                or _decode_aarch64_b_target(word, pc) is not None
                or _decode_aarch64_br_register(word) is not None
                or _is_aarch64_return(word)
            ):
                continue

            if word != 0xD503201F:  # NOP
                registers.clear()

        outgoing_states[block_index] = registers

    reachable_observations = 0
    unreachable_observations = 0
    reachable_helpers = 0
    unreachable_helpers = 0
    reachable_methods = 0
    unreachable_methods = 0
    for block in blocks:
        block_index = block["block_index"]
        block_calls = []
        start = block["instruction_start"]
        end = start + block["instruction_count"]
        for instruction_index in range(start, end):
            for event in calls_at.get(instruction_index, ()):
                block_calls.append({
                    "instruction_index": instruction_index,
                    **event,
                })
        block["reachable"] = block_index in reachable
        block["callsite_observations"] = block_calls
        resolved_helpers = sum(
            "method" in event and event.get("target_kind") != "metadata_method"
            for event in block_calls
        )
        resolved_methods = sum(
            event.get("target_kind") == "metadata_method"
            for event in block_calls
        )
        if block["reachable"]:
            reachable_observations += len(block_calls)
            reachable_helpers += resolved_helpers
            reachable_methods += resolved_methods
        else:
            unreachable_observations += len(block_calls)
            unreachable_helpers += resolved_helpers
            unreachable_methods += resolved_methods

    max_reported_blocks = 512
    return {
        "control_flow_analysis_kind": "bounded_intraprocedural_basic_blocks",
        "control_flow_instruction_count": instruction_count,
        "control_flow_block_count": len(blocks),
        "control_flow_basic_blocks": blocks[:max_reported_blocks],
        "control_flow_basic_blocks_truncated": len(blocks) > max_reported_blocks,
        "control_flow_reachable_callsite_observation_count": reachable_observations,
        "control_flow_unreachable_callsite_observation_count": unreachable_observations,
        "control_flow_reachable_resolved_helper_callsite_count": reachable_helpers,
        "control_flow_unreachable_resolved_helper_callsite_count": unreachable_helpers,
        "control_flow_reachable_resolved_metadata_method_callsite_count":
            reachable_methods,
        "control_flow_unreachable_resolved_metadata_method_callsite_count":
            unreachable_methods,
        "control_flow_conditional_branch_count": conditional_count,
        "control_flow_external_branch_exit_count": external_exit_count,
    }



def _summarize_control_flow_helper_paths(
    control_flow_summary, *, max_paths=64, max_depth=256
):
    """Enumerate bounded simple paths through a previously built method CFG.

    Conditional edges are treated as possible, not evaluated. A back-edge is
    recorded as a cycle exit rather than unrolled. This is a path-shape aid for
    reviewing branch-exclusive helper observations; it is not symbolic
    execution, a runtime trace, or a recovered serializer field order.
    """
    if type(control_flow_summary) is not dict:
        raise ValueError("control-flow summary must be a built-in dict")
    if type(max_paths) is not int or not 1 <= max_paths <= 256:
        raise ValueError("max_paths must be an integer between 1 and 256")
    if type(max_depth) is not int or not 1 <= max_depth <= 1024:
        raise ValueError("max_depth must be an integer between 1 and 1024")

    blocks = control_flow_summary.get("control_flow_basic_blocks")
    if type(blocks) is not list:
        raise ValueError("control-flow blocks must be a built-in list")
    block_count = control_flow_summary.get("control_flow_block_count")
    if type(block_count) is not int or block_count < 0:
        raise ValueError("control-flow block count is invalid")
    has_declared_instruction_count = (
        "control_flow_instruction_count" in control_flow_summary
    )
    declared_instruction_count = control_flow_summary.get(
        "control_flow_instruction_count"
    )
    if has_declared_instruction_count:
        if (
            type(declared_instruction_count) is not int
            or declared_instruction_count < 0
        ):
            raise ValueError("control-flow instruction count is invalid")
        if (
            (block_count == 0 and declared_instruction_count != 0)
            or (block_count > 0 and declared_instruction_count == 0)
        ):
            raise ValueError("control-flow instruction count does not match blocks")
    truncated_flag = control_flow_summary.get(
        "control_flow_basic_blocks_truncated"
    )
    if (
        "control_flow_basic_blocks_truncated" in control_flow_summary
        and type(truncated_flag) is not bool
    ):
        raise ValueError("control-flow truncation flag must be a boolean")
    if has_declared_instruction_count and type(truncated_flag) is not bool:
        raise ValueError(
            "declared instruction windows require a boolean truncation flag"
        )
    if truncated_flag is True or len(blocks) != block_count:
        return {
            "control_flow_path_analysis_kind": "bounded_simple_path_enumeration",
            "control_flow_path_analysis_status": "cfg_truncated",
            "control_flow_path_semantics": (
                "simple paths; back-edges are recorded as cycles, not unrolled"
            ),
            "control_flow_path_limit": max_paths,
            "control_flow_path_depth_limit": max_depth,
            "control_flow_path_count": 0,
            "control_flow_paths": [],
            "control_flow_paths_truncated": True,
            "control_flow_path_cycle_count": 0,
            "control_flow_path_depth_limit_count": 0,
        }
    if not blocks:
        return {
            "control_flow_path_analysis_kind": "bounded_simple_path_enumeration",
            "control_flow_path_analysis_status": "empty",
            "control_flow_path_semantics": (
                "simple paths; back-edges are recorded as cycles, not unrolled"
            ),
            "control_flow_path_limit": max_paths,
            "control_flow_path_depth_limit": max_depth,
            "control_flow_path_count": 0,
            "control_flow_paths": [],
            "control_flow_paths_truncated": False,
            "control_flow_path_cycle_count": 0,
            "control_flow_path_depth_limit_count": 0,
        }

    by_index = {}
    edges_by_index = {}
    allowed_edge_kinds = {
        "fallthrough", "conditional_taken", "conditional_fallthrough",
        "branch_target",
    }
    for block in blocks:
        if type(block) is not dict:
            raise ValueError("each control-flow block must be a built-in dict")
        index = block.get("block_index")
        successors = block.get("successors")
        observations = block.get("callsite_observations")
        if type(index) is not int or not 0 <= index < block_count:
            raise ValueError("control-flow block index is invalid")
        if index in by_index:
            raise ValueError("control-flow block indexes contain duplicates")
        if type(successors) is not list or type(observations) is not list:
            raise ValueError("control-flow successors and observations must be lists")
        if any(
            type(successor) is not int or not 0 <= successor < block_count
            for successor in successors
        ):
            raise ValueError("control-flow successor index is invalid")
        if len(set(successors)) != len(successors):
            raise ValueError("control-flow successors contain duplicates")
        if any(type(item) is not dict for item in observations):
            raise ValueError("callsite observations must be built-in dicts")

        has_instruction_indexes = [
            "instruction_index" in item for item in observations
        ]
        if any(has_instruction_indexes) and not all(has_instruction_indexes):
            raise ValueError(
                "callsite instruction indexes must be present on every observation or none"
            )

        has_instruction_range = (
            "instruction_start" in block or "instruction_count" in block
        )
        if has_instruction_range:
            instruction_start = block.get("instruction_start")
            instruction_count = block.get("instruction_count")
            if (
                type(instruction_start) is not int
                or instruction_start < 0
                or type(instruction_count) is not int
                or instruction_count < 1
            ):
                raise ValueError("control-flow block instruction range is invalid")
        else:
            instruction_start = None
            instruction_count = None
        if has_declared_instruction_count and not has_instruction_range:
            raise ValueError(
                "control-flow blocks require instruction ranges when window count is declared"
            )

        if (
            has_declared_instruction_count
            and instruction_start + instruction_count > declared_instruction_count
        ):
            raise ValueError(
                "control-flow block instruction range is outside declared window"
            )

        previous_instruction_index = None
        if has_instruction_indexes and all(has_instruction_indexes):
            for observation in observations:
                instruction_index = observation["instruction_index"]
                if type(instruction_index) is not int or instruction_index < 0:
                    raise ValueError(
                        "callsite instruction index must be a non-negative integer"
                    )
                if has_instruction_range and not (
                    instruction_start
                    <= instruction_index
                    < instruction_start + instruction_count
                ):
                    raise ValueError(
                        "callsite instruction index is outside its block"
                    )
                if (
                    previous_instruction_index is not None
                    and instruction_index <= previous_instruction_index
                ):
                    raise ValueError(
                        "callsite instruction indexes must be strictly increasing within a block"
                    )
                previous_instruction_index = instruction_index

        if "external_fallthrough_exit" in block and type(
            block["external_fallthrough_exit"]
        ) is not bool:
            raise ValueError("conditional fallthrough-exit flag is invalid")
        condition = None
        if "terminator_condition" in block:
            condition = _validate_control_flow_branch_condition(
                block["terminator_condition"]
            )
            if block.get("terminator") != condition["kind"]:
                raise ValueError("conditional branch predicate does not match terminator")
        if "terminator_flag_producer" in block:
            producer = _validate_control_flow_flag_producer(
                block["terminator_flag_producer"]
            )
            if (
                condition is None
                or condition.get("kind") != "b_cond"
                or not has_instruction_range
            ):
                raise ValueError(
                    "NZCV producers require a ranged B.cond terminator"
                )
            branch_index = instruction_start + instruction_count - 1
            if (
                producer["instruction_index"]
                + producer["intervening_nop_count"] + 1 != branch_index
                or producer["instruction_index"] < instruction_start
            ):
                raise ValueError(
                    "NZCV producer is not adjacent to its B.cond terminator"
                )
        raw_edges = block.get("successor_edges")
        if raw_edges is None:
            # Accept older synthetic summaries, but mark their edge semantics
            # as generic rather than inventing branch/fallthrough provenance.
            normalized_edges = [
                {"target_block": successor, "kind": "successor"}
                for successor in successors
            ]
        else:
            if type(raw_edges) is not list:
                raise ValueError("control-flow successor edges must be a built-in list")
            normalized_edges = []
            seen_edges = set()
            for edge in raw_edges:
                if type(edge) is not dict:
                    raise ValueError("each control-flow successor edge must be a built-in dict")
                target = edge.get("target_block")
                kind = edge.get("kind")
                if type(target) is not int or target not in successors:
                    raise ValueError("control-flow successor edge target is invalid")
                if type(kind) is not str or kind not in allowed_edge_kinds:
                    raise ValueError("control-flow successor edge kind is invalid")
                identity = (target, kind)
                if identity in seen_edges:
                    raise ValueError("control-flow successor edges contain duplicates")
                seen_edges.add(identity)
                normalized_edges.append({"target_block": target, "kind": kind})
            if {edge["target_block"] for edge in normalized_edges} != set(successors):
                raise ValueError("control-flow successor edges do not cover successors")
        conditional_edge_kinds = {
            "conditional_taken", "conditional_fallthrough"
        }
        if any(edge["kind"] in conditional_edge_kinds for edge in normalized_edges):
            if (
                block.get("terminator") not in {
                    "b_cond", "cbz_cbnz", "tbz_tbnz"
                }
                or "terminator_condition" not in block
            ):
                raise ValueError(
                    "conditional successor edges require a matching branch predicate"
                )

        # Newly generated summaries declare their complete instruction window.
        # Validate the corresponding edge/exit contract as well, so a missing
        # edge cannot silently look like a return and an internal edge cannot
        # simultaneously be reported as an external exit. Legacy summaries
        # without an instruction extent retain their historical permissive shape.
        if has_declared_instruction_count:
            if raw_edges is None:
                raise ValueError(
                    "declared instruction windows require explicit successor edges"
                )
            if "terminator" not in block:
                raise ValueError(
                    "declared instruction windows require an explicit terminator"
                )
            for exit_name in (
                "external_branch_exit", "external_fallthrough_exit"
            ):
                if exit_name not in block or type(block[exit_name]) is not bool:
                    raise ValueError(
                        "declared instruction windows require boolean branch and fallthrough exit flags"
                    )

            terminator = block["terminator"]
            edge_kinds = [edge["kind"] for edge in normalized_edges]
            if terminator in {"b_cond", "cbz_cbnz", "tbz_tbnz"}:
                if "terminator_condition" not in block:
                    raise ValueError(
                        "conditional terminator requires a decoded branch predicate"
                    )
                if any(kind not in conditional_edge_kinds for kind in edge_kinds):
                    raise ValueError(
                        "conditional terminator has a non-conditional successor edge"
                    )
                taken_count = edge_kinds.count("conditional_taken")
                fallthrough_count = edge_kinds.count("conditional_fallthrough")
                if taken_count > 1 or fallthrough_count > 1:
                    raise ValueError(
                        "conditional terminator has duplicate branch outcomes"
                    )
                if taken_count == 1 == block["external_branch_exit"]:
                    raise ValueError(
                        "external branch exit flag conflicts with conditional-taken edge"
                    )
                if taken_count == 0 and not block["external_branch_exit"]:
                    raise ValueError(
                        "conditional-taken outcome is neither internal nor marked external"
                    )
                if fallthrough_count == 1 == block["external_fallthrough_exit"]:
                    raise ValueError(
                        "external fallthrough exit flag conflicts with conditional-fallthrough edge"
                    )
                if fallthrough_count == 0 and not block["external_fallthrough_exit"]:
                    raise ValueError(
                        "conditional-fallthrough outcome is neither internal nor marked external"
                    )
            else:
                if block["external_branch_exit"] or block["external_fallthrough_exit"]:
                    raise ValueError(
                        "non-conditional terminator cannot declare conditional exit flags"
                    )
                allowed_by_terminator = {
                    None: {"fallthrough"},
                    "b": {"branch_target"},
                    "indirect_branch": {"branch_target"},
                    "indirect_branch_unresolved": set(),
                    "indirect_tail": set(),
                    "return": set(),
                }
                if terminator not in allowed_by_terminator:
                    raise ValueError("control-flow terminator kind is invalid")
                if any(
                    kind not in allowed_by_terminator[terminator]
                    for kind in edge_kinds
                ):
                    raise ValueError(
                        "successor edge kind is incompatible with terminator"
                    )
                if terminator == "indirect_branch" and len(normalized_edges) != 1:
                    raise ValueError(
                        "resolved indirect branch requires exactly one internal target"
                    )
                if terminator in {
                    "indirect_branch_unresolved", "indirect_tail", "return"
                } and normalized_edges:
                    raise ValueError(
                        "terminal indirect branch or return cannot have successors"
                    )
                if terminator == "b" and len(normalized_edges) > 1:
                    raise ValueError(
                        "unconditional branch cannot have multiple successor edges"
                    )
                if terminator is None:
                    expected_fallthrough = (
                        instruction_start + instruction_count
                        < declared_instruction_count
                    )
                    if len(normalized_edges) != int(expected_fallthrough):
                        raise ValueError(
                            "unterminated block has an inconsistent fallthrough edge"
                        )
        edges_by_index[index] = normalized_edges
        by_index[index] = block

    if set(by_index) != set(range(block_count)):
        raise ValueError("control-flow block indexes are incomplete")
    if 0 not in by_index:
        raise ValueError("control-flow entry block is missing")
    if has_declared_instruction_count:
        expected_start = 0
        for index in range(block_count):
            block = by_index[index]
            instruction_start = block["instruction_start"]
            instruction_count = block["instruction_count"]
            if instruction_start != expected_start:
                raise ValueError(
                    "control-flow block instruction ranges must be contiguous and non-overlapping"
                )
            expected_start += instruction_count
        if expected_start != declared_instruction_count:
            raise ValueError(
                "control-flow block instruction ranges do not cover declared window"
            )

    paths = []
    truncated = False
    cycle_count = 0
    depth_limit_count = 0
    pending = [(0, (0,), frozenset((0,)), ())]

    def append_path(
        block_indexes, exit_kind, *, edges=(), cycle_target=None, next_block=None
    ):
        nonlocal truncated
        if len(paths) >= max_paths:
            truncated = True
            return False
        calls = []
        for block_index in block_indexes:
            block = by_index[block_index]
            for observation in block["callsite_observations"]:
                item = {"block_index": block_index}
                instruction_index = observation.get("instruction_index")
                if type(instruction_index) is int and instruction_index >= 0:
                    item["instruction_index"] = instruction_index
                kind = observation.get("kind")
                if type(kind) is str:
                    item["kind"] = kind
                method = observation.get("method")
                resolution = observation.get("resolution")
                target_kind = observation.get("target_kind")
                if type(method) is str:
                    item["method"] = method
                elif type(resolution) is str:
                    item["resolution"] = resolution
                if type(target_kind) is str:
                    item["target_kind"] = target_kind
                calls.append(item)
        def branch_condition_record(source, target, edge_kind, condition):
            record = {
                "from_block": source,
                "to_block": target,
                "edge_kind": edge_kind,
                "outcome": (
                    "taken" if edge_kind in {
                        "conditional_taken", "conditional_branch_exit"
                    } else "fallthrough"
                ),
                "condition": dict(condition),
            }
            source_block = by_index[source]
            flag_producer = source_block.get("terminator_flag_producer")
            if flag_producer is not None:
                record["flag_producer"] = dict(flag_producer)
            instruction_start = source_block.get("instruction_start")
            instruction_count = source_block.get("instruction_count")
            if (
                type(instruction_start) is int and instruction_start >= 0
                and type(instruction_count) is int and instruction_count >= 1
            ):
                # The index is relative to the bounded method window; never
                # expose or reconstruct a native virtual address here.
                record["instruction_index"] = (
                    instruction_start + instruction_count - 1
                )
            return record

        branch_conditions = []
        for source, target, edge_kind in edges:
            if edge_kind not in {
                "conditional_taken", "conditional_fallthrough"
            }:
                continue
            condition = by_index[source].get("terminator_condition")
            if condition is not None:
                branch_conditions.append(
                    branch_condition_record(source, target, edge_kind, condition)
                )
        if exit_kind in {
            "conditional_branch_exit", "conditional_fallthrough_exit"
        }:
            source = block_indexes[-1]
            condition = by_index[source].get("terminator_condition")
            if condition is not None:
                branch_conditions.append(
                    branch_condition_record(source, None, exit_kind, condition)
                )
        path = {
            "block_indexes": list(block_indexes),
            "edges": [
                {"from_block": source, "to_block": target, "kind": kind}
                for source, target, kind in edges
            ],
            "branch_conditions": branch_conditions,
            "exit_kind": exit_kind,
            "helper_callsite_observations": calls,
        }
        if cycle_target is not None:
            path["cycle_target_block"] = cycle_target
        if next_block is not None:
            path["next_block"] = next_block
        paths.append(path)
        return True

    while pending:
        block_index, path, visited, path_edges = pending.pop()
        block = by_index[block_index]
        successors = block["successors"]
        if not successors:
            terminator = block.get("terminator")
            if terminator == "return":
                exit_kind = "return"
                if not append_path(path, exit_kind, edges=path_edges):
                    break
            elif terminator in {
                "b", "indirect_tail", "indirect_branch",
                "indirect_branch_unresolved",
            }:
                if not append_path(path, "branch_exit", edges=path_edges):
                    break
            elif terminator in {"b_cond", "cbz_cbnz", "tbz_tbnz"}:
                has_conditional_exit = False
                if block.get("external_branch_exit") is True:
                    has_conditional_exit = True
                    if not append_path(
                        path, "conditional_branch_exit", edges=path_edges
                    ):
                        break
                if block.get("external_fallthrough_exit") is True:
                    has_conditional_exit = True
                    if not append_path(
                        path, "conditional_fallthrough_exit", edges=path_edges
                    ):
                        break
                if not has_conditional_exit and not append_path(
                    path, "conditional_window_exit", edges=path_edges
                ):
                    break
            elif not append_path(path, "window_end", edges=path_edges):
                break
            continue

        # A conditional target outside this bounded window is a distinct
        # possible exit in addition to any in-window fallthrough successor.
        if block.get("external_branch_exit") is True:
            if not append_path(
                path, "conditional_branch_exit", edges=path_edges
            ):
                break
        if block.get("external_fallthrough_exit") is True:
            if not append_path(
                path, "conditional_fallthrough_exit", edges=path_edges
            ):
                break

        for edge in reversed(edges_by_index[block_index]):
            successor = edge["target_block"]
            path_edge = (block_index, successor, edge["kind"])
            if successor in visited:
                cycle_count += 1
                if not append_path(
                    path, "cycle", edges=path_edges + (path_edge,),
                    cycle_target=successor,
                ):
                    break
            elif len(path) >= max_depth:
                depth_limit_count += 1
                if not append_path(
                    path, "depth_limit", edges=path_edges + (path_edge,),
                    next_block=successor,
                ):
                    break
            else:
                pending.append((
                    successor,
                    path + (successor,),
                    visited | {successor},
                    path_edges + (path_edge,),
                ))
        if truncated:
            break

    partial = truncated or depth_limit_count > 0
    return {
        "control_flow_path_analysis_kind": "bounded_simple_path_enumeration",
        "control_flow_path_analysis_status": (
            "truncated" if partial
            else "bounded_with_cycles" if cycle_count
            else "bounded"
        ),
        "control_flow_path_semantics": (
            "simple paths; back-edges are recorded as cycles, not unrolled"
        ),
        "control_flow_path_limit": max_paths,
        "control_flow_path_depth_limit": max_depth,
        "control_flow_path_count": len(paths),
        "control_flow_paths": paths,
        "control_flow_paths_truncated": partial,
        "control_flow_path_cycle_count": cycle_count,
        "control_flow_path_depth_limit_count": depth_limit_count,
    }

def _summarize_aarch64_calls(code, start_va, helper_targets):
    """Summarize direct calls to allowlisted serializer helpers without addresses."""
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact built-in bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if type(helper_targets) is not dict:
        raise ValueError("helper targets must be an exact built-in dict")
    for target, labels in helper_targets.items():
        if type(target) is not int or target < 0 or target % 4:
            raise ValueError(
                "helper targets must be non-negative aligned built-in integers"
            )
        if (
            type(labels) not in (list, tuple)
            or any(type(label) is not str or not label for label in labels)
        ):
            raise ValueError(
                "helper target labels must be built-in string lists or tuples "
                "containing non-empty strings"
            )
    sequence = []
    counts = Counter()
    tail_sequence = []
    tail_counts = Counter()
    other_direct = 0
    indirect = 0
    indirect_tail = 0
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset
        target = _decode_aarch64_bl_target(word, pc)
        if target is not None:
            labels = helper_targets.get(target, ())
            if len(labels) == 1:
                label = labels[0]
                sequence.append(label)
                counts[label] += 1
            elif len(labels) > 1:
                label = "ambiguous_serializer_helper_entry"
                sequence.append(label)
                counts[label] += 1
            else:
                other_direct += 1
            continue
        tail_target = _decode_aarch64_b_target(word, pc)
        if tail_target is not None:
            labels = helper_targets.get(tail_target, ())
            if len(labels) == 1:
                label = labels[0]
                tail_sequence.append(label)
                tail_counts[label] += 1
            elif len(labels) > 1:
                label = "ambiguous_serializer_helper_entry"
                tail_sequence.append(label)
                tail_counts[label] += 1
            continue
        if _decode_aarch64_blr_register(word) is not None:
            indirect += 1
        elif _decode_aarch64_br_register(word) is not None:
            indirect_tail += 1
    return {
        "direct_helper_call_sequence": sequence,
        "direct_helper_call_counts": dict(sorted(counts.items())),
        "direct_tail_helper_call_sequence": tail_sequence,
        "direct_tail_helper_call_counts": dict(sorted(tail_counts.items())),
        "direct_calls_not_in_helper_allowlist": other_direct,
        "indirect_call_count": indirect,
        "indirect_tail_call_count": indirect_tail,
    }


def _direct_branch_targets(code, start_va):
    """Return direct AArch64 B/BL destinations from a bounded entry window."""
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    targets = set()
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset
        target = _decode_aarch64_bl_target(word, pc)
        if target is None:
            target = _decode_aarch64_b_target(word, pc)
        if target is not None:
            targets.add(target)
    return targets


def _summarize_named_method_calls(code, start_va, method_targets):
    """Resolve direct B/BL destinations to unique metadata method labels."""
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    direct = Counter()
    tail = Counter()
    unresolved_direct = 0
    unresolved_tail = 0
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset
        target = _decode_aarch64_bl_target(word, pc)
        if target is not None:
            labels = method_targets.get(target, ())
            if len(labels) == 1:
                direct[labels[0]] += 1
            elif len(labels) > 1:
                direct["<ambiguous_method_target>"] += 1
            else:
                unresolved_direct += 1
            continue
        target = _decode_aarch64_b_target(word, pc)
        if target is not None:
            labels = method_targets.get(target, ())
            if len(labels) == 1:
                tail[labels[0]] += 1
            elif len(labels) > 1:
                tail["<ambiguous_method_target>"] += 1
            else:
                unresolved_tail += 1
    return {
        "resolved_direct_method_call_counts": dict(sorted(direct.items())),
        "resolved_direct_tail_method_call_counts": dict(sorted(tail.items())),
        "unresolved_direct_method_call_count": unresolved_direct,
        "unresolved_direct_tail_method_call_count": unresolved_tail,
    }



def _summarize_serializer_deserializer_path_alignment(
    serializer_summary, deserializer_summary
):
    """Compare bounded serializer/deserializer helper-family path multisets.

    Primitive helper prefixes are normalized (serializeInt/deserializeInt ->
    Int). Unresolved and ambiguous observations remain explicit tokens. This
    is a static path-shape comparison, not field order or runtime execution.
    """
    def collect(summary, side):
        if type(summary) is not dict:
            raise ValueError(f"{side} path summary must be a built-in dict")
        paths = summary.get("control_flow_paths")
        path_count = summary.get("control_flow_path_count")
        truncated = summary.get("control_flow_paths_truncated")
        status = summary.get("control_flow_path_analysis_status")
        if type(paths) is not list:
            raise ValueError(f"{side} paths must be a built-in list")
        if len(paths) > MAX_SERIALIZER_ALIGNMENT_PATHS:
            raise ValueError(
                f"{side} path count exceeds {MAX_SERIALIZER_ALIGNMENT_PATHS}"
            )
        if type(path_count) is not int or path_count != len(paths):
            raise ValueError(f"{side} path count does not match its path list")
        if type(truncated) is not bool:
            raise ValueError(f"{side} truncation flag must be a built-in bool")
        if type(status) is not str:
            raise ValueError(f"{side} path status must be a built-in string")

        signatures = Counter()
        unresolved_count = 0
        path_tokens = []
        for path in paths:
            if type(path) is not dict:
                raise ValueError(f"{side} path entries must be built-in dicts")
            exit_kind = path.get("exit_kind")
            observations = path.get("helper_callsite_observations")
            if type(exit_kind) is not str or type(observations) is not list:
                raise ValueError(f"{side} path entry is malformed")
            if len(observations) > MAX_SERIALIZER_ALIGNMENT_OBSERVATIONS:
                raise ValueError(
                    f"{side} path observations exceed "
                    f"{MAX_SERIALIZER_ALIGNMENT_OBSERVATIONS}"
                )
            tokens = []
            for observation in observations:
                if type(observation) is not dict:
                    raise ValueError(
                        f"{side} callsite observations must be built-in dicts"
                    )
                kind = observation.get("kind")
                method = observation.get("method")
                resolution = observation.get("resolution")
                if type(method) is str and method:
                    leaf = method.rsplit("::", 1)[-1]
                    if leaf.startswith("serialize") and len(leaf) > 9:
                        family = leaf[9:]
                    elif leaf.startswith("deserialize") and len(leaf) > 11:
                        family = leaf[11:]
                    else:
                        family = leaf
                    tokens.append(("helper", family))
                elif type(resolution) is str and resolution:
                    if type(kind) is not str:
                        raise ValueError(
                            f"{side} unresolved callsite kind is invalid"
                        )
                    tokens.append(("unresolved", kind, resolution))
                    unresolved_count += 1
                else:
                    raise ValueError(
                        f"{side} callsite observation has no method or resolution"
                    )
            token_sequence = tuple(tokens)
            path_tokens.append(token_sequence)
            signatures[(exit_kind, token_sequence)] += 1
        return (
            signatures, len(paths), unresolved_count, status, truncated,
            path_tokens,
        )

    (
        serializer, serializer_count, serializer_unresolved,
        serializer_status, serializer_truncated, serializer_paths,
    ) = collect(serializer_summary, "serializer")
    (
        deserializer, deserializer_count, deserializer_unresolved,
        deserializer_status, deserializer_truncated, deserializer_paths,
    ) = collect(deserializer_summary, "deserializer")
    path_pair_count = len(serializer_paths) * len(deserializer_paths)
    prefix_lengths = Counter()
    if path_pair_count:
        # Count deserializer paths below each helper-prefix trie node. Each
        # serializer path then accumulates the number of pairs sharing every
        # prefix length without materializing the full Cartesian product.
        trie = {"children": {}}
        for deserializer_path in deserializer_paths:
            node = trie
            for token in deserializer_path:
                child = node["children"].get(token)
                if child is None:
                    child = {"count": 0, "children": {}}
                    node["children"][token] = child
                child["count"] += 1
                node = child

        pairs_with_prefix = Counter()
        for serializer_path in serializer_paths:
            node = trie
            for prefix_length, token in enumerate(serializer_path, 1):
                node = node["children"].get(token)
                if node is None:
                    break
                pairs_with_prefix[prefix_length] += node["count"]

        zero_prefix_pairs = path_pair_count - pairs_with_prefix.get(1, 0)
        if zero_prefix_pairs:
            prefix_lengths[0] = zero_prefix_pairs
        maximum_prefix_length = max(pairs_with_prefix, default=0)
        for prefix_length in range(1, maximum_prefix_length + 1):
            exact_pairs = (
                pairs_with_prefix[prefix_length]
                - pairs_with_prefix.get(prefix_length + 1, 0)
            )
            if exact_pairs:
                prefix_lengths[prefix_length] = exact_pairs
    maximum_common_prefix_length = max(prefix_lengths, default=0)
    maximum_common_prefix_pair_count = prefix_lengths.get(
        maximum_common_prefix_length, 0
    )
    shared_keys = serializer.keys() & deserializer.keys()
    shared_instances = sum(
        min(serializer[key], deserializer[key]) for key in shared_keys
    )
    serializer_only = sum(
        serializer[key] - min(serializer[key], deserializer[key])
        for key in serializer
    )
    deserializer_only = sum(
        deserializer[key] - min(serializer[key], deserializer[key])
        for key in deserializer
    )

    complete_statuses = {"bounded", "bounded_with_cycles", "empty"}
    if (
        serializer_truncated
        or deserializer_truncated
        or serializer_status not in complete_statuses
        or deserializer_status not in complete_statuses
    ):
        comparison_status = "partial"
    elif (
        serializer_status == "bounded_with_cycles"
        or deserializer_status == "bounded_with_cycles"
    ):
        comparison_status = "bounded_with_cycles"
    elif serializer_status == "empty" or deserializer_status == "empty":
        comparison_status = "empty"
    else:
        comparison_status = "bounded"

    def render(counter):
        rendered = []
        for (exit_kind, tokens), occurrences in sorted(
            counter.items(), key=lambda item: repr(item[0])
        ):
            families = []
            unresolved = []
            for token in tokens:
                if token[0] == "helper":
                    families.append(token[1])
                else:
                    unresolved.append({
                        "kind": token[1],
                        "resolution": token[2],
                    })
            rendered.append({
                "exit_kind": exit_kind,
                "helper_families": families,
                "unresolved_observations": unresolved,
                "occurrences": occurrences,
            })
        return rendered

    shared = Counter({
        key: min(serializer[key], deserializer[key])
        for key in shared_keys
    })
    serializer_excess = Counter({
        key: serializer[key] - min(serializer[key], deserializer[key])
        for key in serializer
        if serializer[key] > deserializer[key]
    })
    deserializer_excess = Counter({
        key: deserializer[key] - min(serializer[key], deserializer[key])
        for key in deserializer
        if deserializer[key] > serializer[key]
    })
    return {
        "comparison_kind": "bounded_control_flow_helper_family_path_multiset",
        "comparison_status": comparison_status,
        "path_semantics": (
            "conditional edges are possible; simple paths only; cycles are not unrolled"
        ),
        "field_order_inferred": False,
        "serializer_path_count": serializer_count,
        "deserializer_path_count": deserializer_count,
        "path_pair_count": path_pair_count,
        "maximum_common_helper_prefix_length": maximum_common_prefix_length,
        "maximum_common_helper_prefix_pair_count": maximum_common_prefix_pair_count,
        "common_helper_prefix_length_histogram": [
            {"prefix_length": length, "path_pair_count": count}
            for length, count in sorted(prefix_lengths.items())
        ],
        "shared_path_signature_count": len(shared_keys),
        "shared_path_instance_count": shared_instances,
        "serializer_only_path_instance_count": serializer_only,
        "deserializer_only_path_instance_count": deserializer_only,
        "serializer_unresolved_observation_count": serializer_unresolved,
        "deserializer_unresolved_observation_count": deserializer_unresolved,
        "shared_path_signatures": render(shared),
        "serializer_only_path_signatures": render(serializer_excess),
        "deserializer_only_path_signatures": render(deserializer_excess),
    }


def _compare_login_session_serializer_paths(callsite_summary):
    """Pair metadata-named STSerializer/STDeserializer path summaries."""
    if type(callsite_summary) is not list:
        raise ValueError("callsite summary must be a built-in list")
    groups = defaultdict(lambda: {"serializer": [], "deserializer": []})
    for entry in callsite_summary:
        if type(entry) is not dict:
            raise ValueError("callsite summary entries must be built-in dicts")
        type_name = entry.get("type")
        method_name = entry.get("method")
        image = entry.get("image")
        if type(type_name) is not str or type(image) is not str:
            continue
        if type_name.endswith("STSerializer") and method_name == "serialize":
            groups[(image, type_name[:-len("STSerializer")])]["serializer"].append(entry)
        elif type_name.endswith("STDeserializer") and method_name == "deserialize":
            groups[(image, type_name[:-len("STDeserializer")])]["deserializer"].append(entry)

    comparisons = []
    for (image, message_type), pair in sorted(groups.items()):
        serializers = pair["serializer"]
        deserializers = pair["deserializer"]
        if len(serializers) != 1 or len(deserializers) != 1:
            comparisons.append({
                "image": image,
                "message_type": message_type,
                "serializer_entry_count": len(serializers),
                "deserializer_entry_count": len(deserializers),
                "comparison_status": "unpaired_or_ambiguous",
                "field_order_inferred": False,
            })
            continue
        comparison = _summarize_serializer_deserializer_path_alignment(
            serializers[0], deserializers[0]
        )
        serializer_window_truncated = serializers[0].get(
            "entry_window_truncated", False
        )
        deserializer_window_truncated = deserializers[0].get(
            "entry_window_truncated", False
        )
        if (
            type(serializer_window_truncated) is not bool
            or type(deserializer_window_truncated) is not bool
        ):
            raise ValueError("entry-window truncation flags must be built-in bools")
        if serializer_window_truncated or deserializer_window_truncated:
            comparison["comparison_status"] = "partial"
        comparisons.append({
            "image": image,
            "message_type": message_type,
            "serializer_type": serializers[0]["type"],
            "deserializer_type": deserializers[0]["type"],
            "serializer_entry_window_truncated": serializer_window_truncated,
            "deserializer_entry_window_truncated": deserializer_window_truncated,
            **comparison,
        })
    return comparisons


def _entrypoint_windows(sections, relocations, tables, images, executable):
    """Bound each entry window by the next distinct executable entry in its section."""
    by_section = defaultdict(set)
    for image in images:
        pointer_table = tables.get(image["name"])
        if pointer_table is None:
            continue
        for slot_index in range(image["method_count"]):
            relocation = relocations.get(pointer_table + slot_index * 8)
            if relocation is None or relocation[0] != R_AARCH64_RELATIVE:
                continue
            target = relocation[1]
            matches = [
                name for name, section in executable
                if section["address"] <= target < section["address"] + section["size"]
            ]
            if len(matches) == 1:
                by_section[matches[0]].add(target)
    windows = {}
    for section_name, addresses in by_section.items():
        section = sections[section_name]
        ordered = sorted(addresses)
        section_end = section["address"] + section["size"]
        for index, target in enumerate(ordered):
            next_target = ordered[index + 1] if index + 1 < len(ordered) else section_end
            available = next_target - target
            if available <= 0:
                continue
            size = min(available, MAX_ENTRYPOINT_WINDOW_BYTES)
            size -= size % 4
            if size == 0:
                continue
            windows[(section_name, target)] = (
                size, size != available
            )
    return windows


def inspect_bytes(metadata, elf, apk_sha256=None):
    """Map allowlisted network/serializer methods and summarize direct helper calls."""
    info = _metadata_images(metadata)
    methods = _network_methods(metadata, info)
    network_fields = _network_fields(metadata)
    helper_methods = _network_methods(metadata, info, SERIALIZER_HELPER_METHODS)
    sections, relocations, tables = _module_tables(elf, info["images"])
    executable = [
        (name, section) for name, section in sections.items()
        if section["type"] == 1 and (section["flags"] & 0x4)
    ]

    def resolve(method):
        pointer_table = tables.get(method["image"])
        if pointer_table is None:
            return "module_unresolved", None, None
        slot = pointer_table + method["slot_index"] * 8
        relocation = relocations.get(slot)
        if relocation is None or relocation[0] != R_AARCH64_RELATIVE:
            return "no_relative_relocation", None, None
        target = relocation[1]
        matches = [
            name for name, section in executable
            if section["address"] <= target < section["address"] + section["size"]
        ]
        if len(matches) == 1:
            return "executable_relocation", matches[0], target
        return "target_not_in_executable_section", None, target

    evidence = []
    for method in methods:
        status, target_section, _target = resolve(method)
        evidence.append({
            "category": method["category"],
            "namespace": method["namespace"], "type": method["type"],
            "method": method["method"], "parameter_count": method["parameter_count"],
            "image": method["image"], "entry_status": status,
            "target_section": target_section,
        })
    evidence.sort(key=lambda x: (
        x["namespace"], x["type"], x["method"], x["parameter_count"],
        x["entry_status"],
    ))

    helper_targets = defaultdict(list)
    helper_entrypoints = 0
    for method in helper_methods:
        status, _section, target = resolve(method)
        if status == "executable_relocation":
            helper_entrypoints += 1
            helper_targets[target].append(
                f'{method["namespace"]}.{method["type"]}::{method["method"]}'
            )
    # The ordered-callsite helper accepts only exact built-in containers.
    helper_targets = dict(helper_targets)

    windows = _entrypoint_windows(
        sections, relocations, tables, info["images"], executable
    )
    serializer_windows = []
    network_windows = []
    direct_targets = set()
    indirect_targets = set()

    for method in methods:
        method_key = (method["namespace"], method["type"], method["method"])
        if method["category"] != "network" or method_key not in NETWORK_CALLSITE_METHODS:
            continue
        status, section_name, target = resolve(method)
        if status != "executable_relocation":
            continue
        window = windows.get((section_name, target))
        if window is None:
            continue
        window_bytes, truncated = window
        section = sections[section_name]
        file_offset = section["offset"] + target - section["address"]
        code = _slice(elf, file_offset, window_bytes, "native network method entry window")
        network_windows.append(
            (method, section_name, target, window_bytes, truncated, code)
        )
        direct_targets.update(_direct_branch_targets(code, target))
        indirect_targets.update(
            _relocated_indirect_call_targets(code, target, relocations)
        )

    for method in methods:
        if method["category"] != "login_session_serializer":
            continue
        status, section_name, target = resolve(method)
        if status != "executable_relocation":
            continue
        window = windows.get((section_name, target))
        if window is None:
            continue
        window_bytes, truncated = window
        section = sections[section_name]
        file_offset = section["offset"] + target - section["address"]
        code = _slice(elf, file_offset, window_bytes, "native method entry window")
        serializer_windows.append(
            (method, section_name, target, window_bytes, truncated, code)
        )
        direct_targets.update(_direct_branch_targets(code, target))
        indirect_targets.update(
            _relocated_indirect_call_targets(code, target, relocations)
        )

    method_targets = dict(_all_method_targets(
        metadata, info, tables, relocations, executable,
        direct_targets | indirect_targets,
    ))
    callsite_summary = []
    for method, section_name, target, window_bytes, truncated, code in serializer_windows:
        summary = _summarize_aarch64_calls(code, target, helper_targets)
        named_summary = _summarize_named_method_calls(code, target, method_targets)
        indirect_summary = _summarize_relocated_indirect_calls(
            code, target, relocations, method_targets
        )
        ordered_summary = _summarize_ordered_serializer_helper_calls(
            code, target, relocations, helper_targets
        )
        control_flow_summary = _summarize_control_flow_serializer_helper_blocks(
            code, target, relocations, helper_targets
        )
        control_flow_path_summary = _summarize_control_flow_helper_paths(
            control_flow_summary
        )
        callsite_summary.append({
            "type": method["type"],
            "method": method["method"],
            "image": method["image"],
            "entry_window_kind": "next_distinct_executable_entry_in_section",
            "entry_window_bytes": window_bytes,
            "entry_window_truncated": truncated,
            **summary,
            **named_summary,
            **indirect_summary,
            **ordered_summary,
            **control_flow_summary,
            **control_flow_path_summary,
            "memory_access_summary": summarize_unsigned_immediate_memory_accesses(code),
        })
    callsite_summary.sort(key=lambda x: (x["type"], x["method"]))
    serializer_deserializer_path_comparisons = (
        _compare_login_session_serializer_paths(callsite_summary)
    )

    network_callsite_summary = []
    for method, section_name, target, window_bytes, truncated, code in network_windows:
        helper_summary = _summarize_aarch64_calls(code, target, helper_targets)
        named_summary = _summarize_named_method_calls(code, target, method_targets)
        indirect_summary = _summarize_relocated_indirect_calls(
            code, target, relocations, method_targets
        )
        control_flow_summary = _summarize_control_flow_serializer_helper_blocks(
            code, target, relocations, helper_targets, method_targets=method_targets
        )
        control_flow_path_summary = _summarize_control_flow_helper_paths(
            control_flow_summary
        )
        network_callsite_summary.append({
            "namespace": method["namespace"],
            "type": method["type"],
            "method": method["method"],
            "parameter_count": method["parameter_count"],
            "image": method["image"],
            "entry_window_kind": "next_distinct_executable_entry_in_section",
            "entry_window_bytes": window_bytes,
            "entry_window_truncated": truncated,
            **helper_summary,
            **named_summary,
            **indirect_summary,
            **control_flow_summary,
            **control_flow_path_summary,
            "memory_access_summary": summarize_unsigned_immediate_memory_accesses(code),
        })
    network_callsite_summary.sort(
        key=lambda x: (x["namespace"], x["type"], x["method"], x["parameter_count"])
    )

    receiver_integer_lookup_summary = {
        "status": "not_available",
        "wire_message_id_verified": False,
        "compression_behavior_verified": False,
        "wire_contract_verified": False,
        "apk_compatible": False,
    }
    receiver_window = next((
        item for item in network_windows
        if item[0]["namespace"] == "com.geargames.common.network"
        and item[0]["type"] == "Receiver" and item[0]["method"] == "Cycle"
    ), None)
    networksettings_cctor_window = next((
        item for item in network_windows
        if item[0]["namespace"] == "com.geargames.common.network"
        and item[0]["type"] == "NetworkSettings" and item[0]["method"] == ".cctor"
    ), None)
    deserialize_int_targets = {
        target for target, labels in helper_targets.items()
        if "com.geargames.serialization.SimpleDeserializer::deserializeInt" in labels
    }
    if (
        receiver_window is not None
        and networksettings_cctor_window is not None
        and len(deserialize_int_targets) == 1
    ):
        field_candidate = _networksettings_first_non_default_field(metadata)
        receiver_integer_lookup_summary, lookup_target = _summarize_receiver_integer_lookup(
            receiver_window[5], receiver_window[2],
            networksettings_cctor_window[5], networksettings_cctor_window[2],
            deserialize_int_targets, set(method_targets), field_candidate,
            receiver_window_truncated=receiver_window[4],
            networksettings_cctor_window_truncated=networksettings_cctor_window[4],
        )
        if lookup_target is not None:
            fde_window = _bounded_fde_code_for_target(elf, sections, lookup_target)
            if fde_window is not None:
                fde_size, fde_code = fde_window
                receiver_integer_lookup_summary["callee_fde_entry_resolved"] = True
                receiver_integer_lookup_summary["callee_entry_window_bytes"] = fde_size
                receiver_integer_lookup_summary["callee_hash_bucket_opcode_families_present"] = (
                    _contains_hash_bucket_opcode_families(fde_code)
                )
                receiver_integer_lookup_summary["callee_bucketed_lookup_shape"] = (
                    _summarize_bucketed_lookup_shape(fde_code)
                )

    primitive_helper_summary = []
    for method in helper_methods:
        status, section_name, target = resolve(method)
        if status != "executable_relocation":
            continue
        window = windows.get((section_name, target))
        if window is None:
            continue
        window_bytes, truncated = window
        section = sections[section_name]
        file_offset = section["offset"] + target - section["address"]
        code = _slice(elf, file_offset, window_bytes, "primitive helper entry window")
        summary = _summarize_aarch64_calls(code, target, helper_targets)
        primitive_helper_summary.append({
            "type": method["type"],
            "method": method["method"],
            "image": method["image"],
            "entry_window_kind": "next_distinct_executable_entry_in_section",
            "entry_window_bytes": window_bytes,
            "entry_window_truncated": truncated,
            **summary,
        })
    primitive_helper_summary.sort(key=lambda x: (x["type"], x["method"]))

    return {
        "apk_sha256": apk_sha256,
        "metadata_version": info["version"],
        "metadata_method_definitions": info["method_definitions"],
        "observed_network_methods": sum(
            x["category"] == "network" for x in evidence
        ),
        "observed_login_session_serializers": sum(
            x["category"] == "login_session_serializer" for x in evidence
        ),
        "observed_methods_total": len(evidence),
        "observed_serializer_helper_methods": len(helper_methods),
        "serializer_helper_entrypoints": helper_entrypoints,
        "executable_entrypoints": sum(
            x["entry_status"] == "executable_relocation" for x in evidence
        ),
        "methods": evidence,
        "serializer_callsite_summary": callsite_summary,
        "serializer_deserializer_path_comparisons": serializer_deserializer_path_comparisons,
        "network_callsite_summary": network_callsite_summary,
        "receiver_integer_lookup_summary": receiver_integer_lookup_summary,
        "network_field_summary": network_fields,
        "primitive_helper_callsite_summary": primitive_helper_summary,
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
        "serializer_path_comparison_field_order_inferred": False,
        "interpretation": (
            "Metadata method slots are associated with relocation-backed executable "
            "entries. Serializer and primitive-helper callsite summaries count direct AArch64 BL calls "
            "to allowlisted SimpleSerializer/SimpleDeserializer helpers inside a "
            "bounded entry window ending at the next distinct executable entry "
            "in the same section. Selected Receiver/Sender/dispatcher/helper entry windows also emit "
            "redacted network callsite summaries. A separate bounded Receiver.Cycle pass can trace "
            "the second deserializeInt result into W1 while the receiver is loaded through the "
            "NetworkSettings static_fields first slot; the field name remains a metadata-order "
            "candidate, not a proven FieldInfo-to-static-slot map. An exact FDE-entry window may report co-occurring broad opcode families, "
            "but this does not establish a hash-bucket shape or register/data-flow relationship. "
            "Direct tail branches and indirect tail branches are "
            "reported separately. Direct B/BL targets are resolved against metadata-backed method "
            "entries where unique; unresolved and ambiguous targets remain counts only. Indirect calls "
            "and other direct calls are counted but not assigned field semantics. This is static "
            "evidence only, not a wire protocol, field order, handshake, login, or compatibility proof."
        ),
    }


def inspect_apk(apk_path):
    """Inspect members and fingerprint from one stable, no-follow APK descriptor."""
    metadata, elf, apk_sha256 = _read_apk_members(Path(apk_path))
    return inspect_bytes(metadata, elf, apk_sha256)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline allowlisted IL2CPP network method entry evidence"
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
