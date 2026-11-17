"""Redacted AArch64 unsigned-immediate memory-access evidence.

The module provides both a flat decoder summary and a bounded CFG-aware view.
Neither resolves base-register provenance, identifies managed fields, or proves
runtime execution.
"""
import struct

from tools.aarch64_call_argument_evidence import _build_control_flow_blocks
_MAX_CODE_WINDOW_BYTES = 64 * 1024
_MAX_REPORTED_ACCESSES = 512


def decode_unsigned_immediate_memory_access(word):
    """Decode integer LDR/STR unsigned-immediate addressing, or return None.

    Supported operations are the non-sign-extending integer load/store forms
    with unsigned scaled immediate offsets. SIMD/vector, sign-extending,
    unscaled, pre/post-indexed, pair and atomic forms are deliberately omitted.
    """
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    # The V bit distinguishes SIMD/FP encodings that share the major opcode.
    if word & (1 << 26):
        return None
    if (word & 0x3B000000) != 0x39000000:
        return None

    opc = (word >> 22) & 0x3
    if opc not in (0, 1):  # STR / LDR only; omit sign-extending and PRFM forms.
        return None

    size = (word >> 30) & 0x3
    access_bytes = 1 << size
    base = (word >> 5) & 0x1F
    target = word & 0x1F
    scaled_offset = ((word >> 10) & 0xFFF) * access_bytes
    register_prefix = "x" if access_bytes == 8 else "w"

    if base == 31:
        base_register = "sp"
    else:
        base_register = f"x{base}"
    if target == 31:
        target_register = f"{register_prefix}zr"
    else:
        target_register = f"{register_prefix}{target}"

    return {
        "operation": "load" if opc == 1 else "store",
        "access_bytes": access_bytes,
        "base_register": base_register,
        "target_register": target_register,
        "byte_offset": scaled_offset,
    }


def summarize_unsigned_immediate_memory_accesses(code, *, max_accesses=128):
    """Summarize bounded unsigned-immediate integer loads/stores in one window.

    This is a linear instruction scan. An access may be on a cold or
    unreachable branch, and the base register may refer to stack, object,
    static, heap or another region. The reported byte_offset is the encoded
    displacement from that unknown base, not a managed-field offset.
    """
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact immutable bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window length must be a multiple of four")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if type(max_accesses) is not int or not 1 <= max_accesses <= _MAX_REPORTED_ACCESSES:
        raise ValueError("max_accesses must be an integer in range 1..512")

    instruction_count = len(code) // 4
    accesses = []
    total = 0
    for instruction_index in range(instruction_count):
        word = int.from_bytes(code[instruction_index * 4:instruction_index * 4 + 4], "little")
        decoded = decode_unsigned_immediate_memory_access(word)
        if decoded is None:
            continue
        total += 1
        if len(accesses) < max_accesses:
            accesses.append({
                "instruction_index": instruction_index,
                **decoded,
            })

    return {
        "analysis_kind": "linear_unsigned_immediate_integer_load_store",
        "instruction_count": instruction_count,
        "memory_access_count": total,
        "memory_accesses": accesses,
        "memory_accesses_truncated": total > len(accesses),
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
    }


def summarize_control_flow_memory_accesses(code, start_va, *, max_accesses=128):
    """Summarize memory accesses with structural reachability in a bounded CFG.

    Supported conditional branches contribute both in-window successors;
    conditions are not evaluated. Supported unconditional branches and
    recognized indirect branches/returns shape the graph. Unknown branch
    encodings are not proven, so this is a conservative helper over the
    repository's documented branch subset, not a complete disassembler.

    Each event is retained in instruction order and marked
    statically_reachable. This means reachable in the constructed graph, not
    executed at runtime. The base register remains unresolved and byte_offset
    is only the encoded displacement from that base.
    """
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact immutable bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window length must be a multiple of four")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if (type(start_va) is not int or not 0 <= start_va <= 0xFFFFFFFFFFFFFFFF
            or start_va % 4):
        raise ValueError("start_va must be an aligned unsigned 64-bit address")
    if code and start_va > 0xFFFFFFFFFFFFFFFF - (len(code) - 4):
        raise ValueError("AArch64 code window exceeds the unsigned 64-bit address space")
    if (type(max_accesses) is not int
            or not 1 <= max_accesses <= _MAX_REPORTED_ACCESSES):
        raise ValueError("max_accesses must be an integer in range 1..512")

    instruction_count = len(code) // 4
    words = list(struct.unpack("<" + "I" * instruction_count, code)) if code else []
    blocks, successors = _build_control_flow_blocks(words, start_va)

    reachable_blocks = set()
    pending = [0] if blocks else []
    while pending:
        block_index = pending.pop()
        if block_index in reachable_blocks:
            continue
        reachable_blocks.add(block_index)
        pending.extend(successors[block_index] - reachable_blocks)

    instruction_blocks = [None] * instruction_count
    for block_index, (block_start, block_end) in enumerate(blocks):
        for instruction_index in range(block_start, block_end):
            instruction_blocks[instruction_index] = block_index

    accesses = []
    total = 0
    reachable_total = 0
    unreachable_total = 0
    for instruction_index, word in enumerate(words):
        decoded = decode_unsigned_immediate_memory_access(word)
        if decoded is None:
            continue
        block_index = instruction_blocks[instruction_index]
        statically_reachable = block_index in reachable_blocks
        total += 1
        if statically_reachable:
            reachable_total += 1
        else:
            unreachable_total += 1
        if len(accesses) < max_accesses:
            accesses.append({
                "instruction_index": instruction_index,
                "block_index": block_index,
                "statically_reachable": statically_reachable,
                **decoded,
            })

    return {
        "analysis_kind": "bounded_intraprocedural_cfg_unsigned_immediate_integer_load_store",
        "instruction_count": instruction_count,
        "basic_block_count": len(blocks),
        "statically_reachable_block_count": len(reachable_blocks),
        "conditional_edges_assume_both_outcomes": True,
        "path_conditions_evaluated": False,
        "memory_access_count": total,
        "statically_reachable_memory_access_count": reachable_total,
        "statically_unreachable_memory_access_count": unreachable_total,
        "memory_accesses": accesses,
        "memory_accesses_truncated": total > len(accesses),
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
    }
