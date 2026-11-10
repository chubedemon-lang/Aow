"""Read-only native entry-point evidence for allowlisted IL2CPP network methods.

Only method names and relocation status are emitted. Native addresses, raw
instructions, packet bytes, endpoints and proprietary assets remain private.
This is static registration evidence, not a wire-protocol compatibility proof.
"""
import argparse
import bisect
import hashlib
import json
import struct
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from tools.il2cpp_codegen_inventory import (
    ARM64_IL2CPP_MEMBER, MAX_APK, MAX_ELF, MAX_METADATA, METADATA_MEMBER,
    R_AARCH64_RELATIVE, CodegenInventoryError, _contains, _elf_sections,
    _metadata_images, _slice, _table,
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
        "InternalGetMessageType", "GetMessageType",
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
MAX_ENTRYPOINT_WINDOW_BYTES = 64 * 1024


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


def _decode_aarch64_blr_register(word):
    """Return the BLR source register, or None for another instruction."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFFFFFC1F) != 0xD63F0000:
        return None
    return (word >> 5) & 0x1F


def _decode_aarch64_br_register(word):
    """Return the BR source register, or None for another instruction."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFFFFFC1F) != 0xD61F0000:
        return None
    return (word >> 5) & 0x1F


def _relocated_indirect_call_events(code, start_va, relocations):
    """Resolve only contiguous ADRP/ADD/LDR/BLR-or-BR relocation-backed chains.

    Any unrecognized instruction clears the small abstract register state.
    This deliberately misses ordinary virtual calls and runtime-computed
    pointers rather than guessing their targets.
    """
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if not isinstance(relocations, dict):
        raise ValueError("relocations must be a mapping")

    registers = {}
    events = []
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset

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
            if (isinstance(relocation, tuple) and len(relocation) == 2
                    and relocation[0] == R_AARCH64_RELATIVE
                    and type(relocation[1]) is int and relocation[1] >= 0):
                registers[target_register] = relocation[1]
            else:
                registers.pop(target_register, None)
            continue

        call_register = _decode_aarch64_blr_register(word)
        if call_register is not None:
            events.append(("call", registers.get(call_register)))
            registers.clear()
            continue

        tail_register = _decode_aarch64_br_register(word)
        if tail_register is not None:
            events.append(("tail", registers.get(tail_register)))
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
    """Resolve statically loaded indirect calls to unique metadata method labels."""
    calls = Counter()
    tails = Counter()
    unresolved_calls = 0
    unresolved_tails = 0
    ambiguous_calls = 0
    ambiguous_tails = 0
    for kind, target in _relocated_indirect_call_events(code, start_va, relocations):
        labels = method_targets.get(target, ()) if target is not None else ()
        if len(labels) == 1:
            (calls if kind == "call" else tails)[labels[0]] += 1
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
        "resolved_indirect_tail_method_call_counts": dict(sorted(tails.items())),
        "unresolved_indirect_call_count": unresolved_calls,
        "unresolved_indirect_tail_call_count": unresolved_tails,
        "ambiguous_indirect_call_count": ambiguous_calls,
        "ambiguous_indirect_tail_call_count": ambiguous_tails,
    }


def _summarize_aarch64_calls(code, start_va, helper_targets):
    """Summarize direct calls to allowlisted serializer helpers without addresses."""
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
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
        if (word & 0xFFFFFC1F) == 0xD63F0000:
            indirect += 1
        elif (word & 0xFFFFFC1F) == 0xD61F0000:
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
                size, available > MAX_ENTRYPOINT_WINDOW_BYTES
            )
    return windows


def inspect_bytes(metadata, elf, apk_sha256=None):
    """Map allowlisted network/serializer methods and summarize direct helper calls."""
    info = _metadata_images(metadata)
    methods = _network_methods(metadata, info)
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

    windows = _entrypoint_windows(
        sections, relocations, tables, info["images"], executable
    )
    serializer_windows = []
    direct_targets = set()
    indirect_targets = set()
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

    method_targets = _all_method_targets(
        metadata, info, tables, relocations, executable,
        direct_targets | indirect_targets,
    )
    callsite_summary = []
    for method, section_name, target, window_bytes, truncated, code in serializer_windows:
        summary = _summarize_aarch64_calls(code, target, helper_targets)
        named_summary = _summarize_named_method_calls(code, target, method_targets)
        indirect_summary = _summarize_relocated_indirect_calls(
            code, target, relocations, method_targets
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
        })
    callsite_summary.sort(key=lambda x: (x["type"], x["method"]))

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
        "primitive_helper_callsite_summary": primitive_helper_summary,
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
        "interpretation": (
            "Metadata method slots are associated with relocation-backed executable "
            "entries. Serializer and primitive-helper callsite summaries count direct AArch64 BL calls "
            "to allowlisted SimpleSerializer/SimpleDeserializer helpers inside a "
            "bounded entry window ending at the next distinct executable entry "
            "in the same section. Direct tail branches and indirect tail branches are reported separately. Direct B/BL targets are resolved against metadata-backed method entries where unique; unresolved and ambiguous targets remain counts only. Indirect calls and other direct calls are counted "
            "but not assigned field semantics. This is static evidence only, not "
            "a wire protocol, field order, handshake, login, or compatibility proof."
        ),
    }


def inspect_apk(apk_path):
    """Read only bounded metadata and arm64 libil2cpp members from a local APK."""
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
