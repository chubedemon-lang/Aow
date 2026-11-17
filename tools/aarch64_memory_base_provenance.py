"""Bounded, redacted AArch64 memory-base provenance observations.

Tracks only ADRP/ADD/MOV and relocation-backed 64-bit LDR chains inside a
conservative intraprocedural CFG. Absolute addresses are used internally and
never emitted. This is static evidence, not a runtime trace or field resolver.
"""
import struct

from tools.aarch64_call_argument_evidence import (
    _CALLER_SAVED_REGISTERS,
    _build_control_flow_blocks,
    _decode_add_immediate,
    _decode_bl_target,
    _decode_conditional_branch_target,
    _decode_move_register,
    _decode_unconditional_branch_target,
    _is_indirect_branch,
    _is_indirect_call,
)
from tools.aarch64_memory_access_evidence import (
    decode_unsigned_immediate_memory_access,
)

_MAX_CODE_WINDOW_BYTES = 64 * 1024
_MAX_REPORTED_ACCESSES = 512
_MAX_RELOCATION_TARGETS = 200_000
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_NOP = 0xD503201F


def _sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def _decode_adrp(word, pc):
    """Return (destination register, page address) for ADRP, else None."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or not 0 <= pc <= _U64_MAX or pc % 4):
        return None
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    page_delta = _sign_extend(immediate, 21) << 12
    address = (pc & ~0xFFF) + page_delta
    if not 0 <= address <= _U64_MAX:
        return None
    return word & 0x1F, address


def _validate_relocation_targets(relocation_targets):
    if relocation_targets is None:
        return {}
    if type(relocation_targets) is not dict:
        raise ValueError("relocation_targets must be an exact dict")
    if len(relocation_targets) > _MAX_RELOCATION_TARGETS:
        raise ValueError("relocation target map exceeds the analysis limit")
    for slot, target in relocation_targets.items():
        if (type(slot) is not int or not 0 <= slot <= _U64_MAX
                or type(target) is not int or not 0 <= target <= _U64_MAX):
            raise ValueError("relocation targets must map unsigned 64-bit integers")
    return relocation_targets


def summarize_control_flow_memory_base_provenance(
    code, start_va, *, relocation_targets=None, max_accesses=128,
):
    """Summarize memory-access base origins without emitting absolute addresses.

    Recognized origins are stack_pointer, adrp_derived_address,
    relocation_loaded_pointer, and unknown. State crosses only a unique
    forward CFG predecessor. Calls clobber modeled caller-saved registers;
    unknown instructions clear state. Conditional edges assume both outcomes.
    """
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("AArch64 code window must be exact bytes and word aligned")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if (type(start_va) is not int or not 0 <= start_va <= _U64_MAX
            or start_va % 4):
        raise ValueError("start_va must be an aligned unsigned 64-bit address")
    if code and start_va > _U64_MAX - (len(code) - 4):
        raise ValueError("AArch64 code window exceeds the unsigned 64-bit address space")
    if (type(max_accesses) is not int
            or not 1 <= max_accesses <= _MAX_REPORTED_ACCESSES):
        raise ValueError("max_accesses must be an integer in range 1..512")
    relocations = _validate_relocation_targets(relocation_targets)

    instruction_count = len(code) // 4
    words = list(struct.unpack("<" + "I" * instruction_count, code)) if code else []
    blocks, successors = _build_control_flow_blocks(words, start_va)

    reachable = set()
    pending = [0] if blocks else []
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pending.extend(successors[current] - reachable)

    predecessors = [set() for _ in blocks]
    for source in reachable:
        for destination in successors[source]:
            if destination in reachable:
                predecessors[destination].add(source)

    outgoing_states = {}
    observations = []
    total_accesses = sum(
        decode_unsigned_immediate_memory_access(word) is not None
        for word in words
    )
    reachable_accesses = 0
    known_provenance_accesses = 0

    for block_index, (block_start, block_end) in enumerate(blocks):
        if block_index not in reachable:
            continue
        incoming = predecessors[block_index]
        if block_index == 0 or len(incoming) != 1:
            registers = {}
        else:
            predecessor = next(iter(incoming))
            if (blocks[predecessor][0] < block_start
                    and predecessor in outgoing_states):
                registers = dict(outgoing_states[predecessor])
            else:
                registers = {}

        for instruction_index in range(block_start, block_end):
            word = words[instruction_index]
            pc = start_va + instruction_index * 4

            adrp = _decode_adrp(word, pc)
            if adrp is not None:
                destination, address = adrp
                if destination != 31:
                    registers[destination] = (
                        "adrp_derived_address", address, instruction_index, 1
                    )
                continue

            add = _decode_add_immediate(word)
            if add is not None:
                destination, source, immediate, width_mask = add
                if width_mask == _U64_MAX and source in registers:
                    kind, value, _definition, depth = registers[source]
                    result = value + immediate
                    if result <= _U64_MAX:
                        registers[destination] = (
                            kind, result, instruction_index, depth + 1
                        )
                    else:
                        registers.pop(destination, None)
                else:
                    registers.pop(destination, None)
                continue

            move = _decode_move_register(word)
            if move is not None:
                destination, source, width_mask = move
                if destination != 31:
                    if width_mask == _U64_MAX and source in registers:
                        kind, value, definition, depth = registers[source]
                        registers[destination] = (
                            kind, value, definition, depth + 1
                        )
                    else:
                        registers.pop(destination, None)
                continue

            access = decode_unsigned_immediate_memory_access(word)
            if access is not None:
                base = (word >> 5) & 0x1F
                target = word & 0x1F
                if base == 31:
                    provenance = "stack_pointer"
                    definition = None
                    depth = 0
                    base_state = None
                else:
                    base_state = registers.get(base)
                    if base_state is None:
                        provenance = "unknown"
                        definition = None
                        depth = 0
                    else:
                        provenance, _address, definition, depth = base_state
                reachable_accesses += 1
                if provenance != "unknown":
                    known_provenance_accesses += 1
                if len(observations) < max_accesses:
                    observations.append({
                        "instruction_index": instruction_index,
                        "operation": access["operation"],
                        "access_bytes": access["access_bytes"],
                        "base_register": access["base_register"],
                        "base_provenance": provenance,
                        "base_definition_instruction_index": definition,
                        "base_derivation_depth": depth,
                    })

                if access["operation"] == "load" and target != 31:
                    registers.pop(target, None)
                    if access["access_bytes"] == 8 and base_state is not None:
                        effective_address = base_state[1] + access["byte_offset"]
                        relocated_target = relocations.get(effective_address)
                        if relocated_target is not None:
                            registers[target] = (
                                "relocation_loaded_pointer",
                                relocated_target,
                                instruction_index,
                                1,
                            )
                continue

            if (_decode_bl_target(word, pc) is not None
                    or _is_indirect_call(word)):
                for register in _CALLER_SAVED_REGISTERS:
                    registers.pop(register, None)
                continue

            if (_decode_conditional_branch_target(word, pc) is not None
                    or _decode_unconditional_branch_target(word, pc) is not None
                    or _is_indirect_branch(word)
                    or word == _NOP):
                continue

            registers.clear()

        outgoing_states[block_index] = registers

    return {
        "analysis_kind": "bounded_cfg_memory_base_provenance",
        "instruction_count": instruction_count,
        "memory_access_count": total_accesses,
        "statically_reachable_memory_access_count": reachable_accesses,
        "statically_unreachable_memory_access_count": total_accesses - reachable_accesses,
        "memory_accesses_with_known_base_provenance": known_provenance_accesses,
        "memory_accesses": observations,
        "memory_accesses_truncated": reachable_accesses > len(observations),
        "absolute_addresses_emitted": False,
        "raw_instructions_emitted": False,
    }
