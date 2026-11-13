"""Redacted AArch64 delegate method-pointer argument evidence.

This bounded CFG pass follows only ADR/ADRP, 64-bit ADD-immediate,
relocation-backed LDR X, and unshifted MOV X copies. It reports metadata
method labels at allowlisted direct delegate-constructor calls, never pointer
values, addresses, instructions, APK bytes, or packet data.

The configured argument register is a static candidate only. This is not a
complete AArch64 emulator, ABI proof, delegate runtime trace, or wire contract.
"""
import struct

from tools.aarch64_call_argument_evidence import (
    _CALLER_SAVED_REGISTERS,
    _NOP,
    _build_control_flow_blocks,
    _decode_bl_target,
    _decode_conditional_branch_target,
    _decode_move_register,
    _decode_unconditional_branch_target,
    _is_indirect_branch,
    _is_indirect_call,
)
from tools.il2cpp_codegen_inventory import R_AARCH64_RELATIVE

_MAX_CODE_WINDOW_BYTES = 64 * 1024
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _decode_adr(word, pc):
    if (word & 0x9F000000) != 0x10000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    destination = word & 0x1F
    if destination == 31:
        return None
    return destination, pc + _sign_extend(immediate, 21)


def _decode_adrp(word, pc):
    if (word & 0x9F000000) != 0x90000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    destination = word & 0x1F
    if destination == 31:
        return None
    page = (pc & ~0xFFF) + (_sign_extend(immediate, 21) << 12)
    return destination, page


def _decode_add_x_immediate(word):
    if (word & 0xFF800000) != 0x91000000:
        return None
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    if destination == 31 or source == 31:
        return None
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    return destination, source, immediate


def _decode_ldr_x_unsigned(word):
    if (word & 0xFFC00000) != 0xF9400000:
        return None
    destination = word & 0x1F
    base = (word >> 5) & 0x1F
    if destination == 31 or base == 31:
        return None
    offset = ((word >> 10) & 0xFFF) * 8
    return destination, base, offset


def _method_labels(labels):
    """Return labels only when every metadata association is representable."""
    if not isinstance(labels, (tuple, list, set, frozenset)):
        return []
    # Filtering malformed entries could turn [valid, invalid] into a false
    # unique match. Fail closed instead of silently dropping an association.
    if any(not isinstance(label, str) or not label for label in labels):
        return []
    return sorted(labels)


def _matches_target_prefix(method_label, prefixes):
    """Match an allowlisted method suffix only at a type-name boundary."""
    method_name = method_label.split("/p", 1)[0]
    return any(
        method_name == prefix or method_name.endswith("." + prefix)
        for prefix in prefixes
    )


def summarize_delegate_method_pointer_arguments(
    code,
    start_va,
    method_targets,
    relocations,
    *,
    target_prefixes=("OnMessageReceivedDelegate::.ctor",),
    argument_registers=(2,),
):
    """Summarize candidate method-pointer arguments at delegate constructors.

    The default x2 register is a candidate for the second declared managed
    constructor parameter on the observed AArch64 call shape; it is not an ABI
    proof. The caller must provide metadata-backed method targets and ELF
    relocations from the same authorized offline analysis pass.

    A unique metadata method label is emitted only when the tracked register
    value exactly matches one metadata-backed executable entry. Missing,
    ambiguous, or unsupported values are reported without publishing the
    underlying address.
    """
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if not isinstance(method_targets, dict) or not isinstance(relocations, dict):
        raise ValueError("method_targets and relocations must be mappings")
    if (
        not isinstance(target_prefixes, (tuple, list, set, frozenset))
        or not target_prefixes
        or any(not isinstance(item, str) or not item for item in target_prefixes)
    ):
        raise ValueError("target_prefixes must be a non-empty collection of strings")
    if (
        not isinstance(argument_registers, (tuple, list))
        or not argument_registers
        or any(type(item) is not int or not 0 <= item <= 7 for item in argument_registers)
        or len(set(argument_registers)) != len(argument_registers)
    ):
        raise ValueError("argument_registers must be unique register indexes in 0..7")
    if not code:
        return []

    words = list(struct.unpack("<" + "I" * (len(code) // 4), code))
    blocks, successors = _build_control_flow_blocks(words, start_va)
    if not blocks:
        return []

    reachable = set()
    pending = [0]
    while pending:
        block_index = pending.pop()
        if block_index in reachable:
            continue
        reachable.add(block_index)
        pending.extend(successors[block_index] - reachable)

    predecessors = [set() for _ in blocks]
    for source in reachable:
        for destination in successors[source]:
            if destination in reachable:
                predecessors[destination].add(source)

    call_ordinals = {}
    ordinal = 0
    for index, word in enumerate(words):
        if _decode_bl_target(word, start_va + index * 4) is not None:
            call_ordinals[index] = ordinal
            ordinal += 1

    outgoing_states = {}
    observations = []
    for block_index, (block_start, block_end) in enumerate(blocks):
        if block_index not in reachable:
            continue

        incoming = predecessors[block_index]
        if block_index == 0 or len(incoming) != 1:
            registers = {}
        else:
            predecessor = next(iter(incoming))
            if (
                predecessor < block_index
                and blocks[predecessor][0] < block_start
                and predecessor in outgoing_states
            ):
                registers = dict(outgoing_states[predecessor])
            else:
                # Do not merge joins or iterate backedges.
                registers = {}

        for instruction_index in range(block_start, block_end):
            word = words[instruction_index]
            pc = start_va + instruction_index * 4

            adr = _decode_adr(word, pc)
            if adr is not None:
                destination, address = adr
                registers[destination] = address & _MASK64
                continue

            adrp = _decode_adrp(word, pc)
            if adrp is not None:
                destination, address = adrp
                registers[destination] = address & _MASK64
                continue

            add = _decode_add_x_immediate(word)
            if add is not None:
                destination, source, immediate = add
                if source in registers:
                    registers[destination] = (registers[source] + immediate) & _MASK64
                else:
                    registers.pop(destination, None)
                continue

            load = _decode_ldr_x_unsigned(word)
            if load is not None:
                destination, base_register, offset = load
                base = registers.get(base_register)
                relocation = None
                if base is not None and base <= _MASK64 - offset:
                    relocation = relocations.get(base + offset)
                if (
                    isinstance(relocation, tuple)
                    and len(relocation) == 2
                    and relocation[0] == R_AARCH64_RELATIVE
                    and type(relocation[1]) is int
                    and 0 <= relocation[1] <= _MASK64
                ):
                    registers[destination] = relocation[1]
                else:
                    registers.pop(destination, None)
                continue

            move = _decode_move_register(word)
            if move is not None:
                destination, source, width_mask = move
                if width_mask == _MASK64 and destination != 31:
                    if source == 31:
                        registers[destination] = 0
                    elif source in registers:
                        registers[destination] = registers[source]
                    else:
                        registers.pop(destination, None)
                else:
                    # W-register copies and writes to XZR are not pointer evidence.
                    if destination != 31:
                        registers.pop(destination, None)
                continue

            target = _decode_bl_target(word, pc)
            if target is not None:
                labels = _method_labels(method_targets.get(target, ()))
                if len(labels) == 1 and _matches_target_prefix(
                    labels[0], target_prefixes
                ):
                    pointer_arguments = {}
                    for register in argument_registers:
                        name = f"x{register}"
                        if register not in registers:
                            pointer_arguments[name] = {"resolution": "unknown"}
                            continue
                        candidate_labels = _method_labels(
                            method_targets.get(registers[register], ())
                        )
                        if len(candidate_labels) == 1:
                            pointer_arguments[name] = {
                                "resolution": "unique_metadata_method",
                                "method": candidate_labels[0],
                            }
                        elif len(candidate_labels) > 1:
                            pointer_arguments[name] = {
                                "resolution": "ambiguous_metadata_method"
                            }
                        else:
                            pointer_arguments[name] = {
                                "resolution": "unresolved_metadata_method"
                            }
                    observations.append({
                        "linear_window_call_ordinal": call_ordinals[instruction_index],
                        "control_flow_block_index": block_index,
                        "instruction_index": instruction_index,
                        "target_method": labels[0],
                        "candidate_method_pointer_arguments": pointer_arguments,
                    })
                for register in _CALLER_SAVED_REGISTERS:
                    registers.pop(register, None)
                continue

            if _is_indirect_call(word):
                for register in _CALLER_SAVED_REGISTERS:
                    registers.pop(register, None)
                continue

            if (
                _decode_conditional_branch_target(word, pc) is not None
                or _decode_unconditional_branch_target(word, pc) is not None
                or _is_indirect_branch(word)
            ):
                continue

            if word != _NOP:
                registers.clear()

        outgoing_states[block_index] = registers

    return sorted(
        observations,
        key=lambda item: item["linear_window_call_ordinal"],
    )
