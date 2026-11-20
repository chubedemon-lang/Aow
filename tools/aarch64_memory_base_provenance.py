"""Bounded, redacted AArch64 memory-base provenance observations.

Tracks ADR/ADRP/ADD/SUB/MOV, stack-pointer-derived addresses and relocation-backed
64-bit LDR chains inside a conservative intraprocedural CFG. Absolute
addresses are used internally and never emitted. This is static evidence,
not a runtime trace or field resolver.
"""
from bisect import bisect_right
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
    decode_integer_immediate_memory_access,
)

_MAX_CODE_WINDOW_BYTES = 64 * 1024
_MAX_REPORTED_ACCESSES = 512
_MAX_RELOCATION_TARGETS = 200_000
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_NOP = 0xD503201F


def _sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def _decode_adr(word, pc):
    """Return (destination register, byte address) for ADR, else None."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or not 0 <= pc <= _U64_MAX or pc % 4):
        return None
    if (word & 0x9F000000) != 0x10000000:
        return None
    immediate = (((word >> 5) & 0x7FFFF) << 2) | ((word >> 29) & 0x3)
    address = pc + _sign_extend(immediate, 21)
    if not 0 <= address <= _U64_MAX:
        return None
    return word & 0x1F, address


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


def _decode_ldr_literal(word, pc):
    """Return (destination register, literal-slot address) for 64-bit LDR literal."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or not 0 <= pc <= _U64_MAX or pc % 4):
        return None
    # LDR Xt, label has the fixed 64-bit literal encoding 0x58xxxxxx.
    # Keep LDR Wt, LDRSW and PRFM literal forms outside this pointer analysis.
    if (word & 0xFF000000) != 0x58000000:
        return None
    displacement = _sign_extend((word >> 5) & 0x7FFFF, 19) << 2
    address = pc + displacement
    if not 0 <= address <= _U64_MAX:
        return None
    return word & 0x1F, address


def _decode_add_from_stack_pointer(word):
    """Return (destination, immediate) for 64-bit ADD Xd, SP, #imm."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or (word & 0x7F800000) != 0x11000000
            or not (word & 0x80000000)):
        return None
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    # In ADD (immediate), Rn=31 denotes SP. Keep Xd=31 out of this
    # transfer because it writes SP itself rather than a general register.
    if source != 31 or destination == 31:
        return None
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    return destination, immediate


def _decode_sub_immediate(word):
    """Return (destination, source, immediate) for unflagged 64-bit SUB Xd, Xn/SP, #imm."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    # sf=1, op=1, S=0: exclude 32-bit SUB and flag-setting SUBS forms.
    if (word & 0xFF800000) != 0xD1000000:
        return None
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    return destination, source, immediate


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


def _validate_known_static_cells(known_static_cells):
    if known_static_cells is None:
        return None
    if type(known_static_cells) not in (tuple, list):
        raise ValueError("known_static_cells must be a built-in tuple or list")
    if len(known_static_cells) > _MAX_RELOCATION_TARGETS:
        raise ValueError("known static cell list exceeds the analysis limit")
    if any(
        type(address) is not int or not 0 <= address <= _U64_MAX - 7
        for address in known_static_cells
    ):
        raise ValueError("known static cells must be valid unsigned 64-bit 8-byte ranges")
    if len(set(known_static_cells)) != len(known_static_cells):
        raise ValueError("known_static_cells must not contain duplicates")
    return tuple(sorted(known_static_cells))


def _memory_access_overlaps_known_static_cell(base_state, access, known_static_cells):
    if base_state is None or base_state[1] is None:
        return False
    effective_address = base_state[1] + access["byte_offset"]
    access_end = effective_address + access["access_bytes"]
    if (
        not 0 <= effective_address <= _U64_MAX
        or access_end > _U64_MAX + 1
        or access_end <= effective_address
    ):
        return False
    candidate_index = bisect_right(known_static_cells, access_end - 1) - 1
    return (
        candidate_index >= 0
        and known_static_cells[candidate_index] + 8 > effective_address
    )

def _load_exactly_matches_known_static_cell(base_state, access, known_static_cells):
    """Return true only for an exact 64-bit load from a known eight-byte cell."""
    if (
        access["operation"] != "load"
        or access["access_bytes"] != 8
        or base_state is None
        or base_state[1] is None
    ):
        return False
    effective_address = base_state[1] + access["byte_offset"]
    if not 0 <= effective_address <= _U64_MAX - 7:
        return False
    candidate_index = bisect_right(known_static_cells, effective_address) - 1
    return (
        candidate_index >= 0
        and known_static_cells[candidate_index] == effective_address
    )


def summarize_control_flow_memory_base_provenance(
    code, start_va, *, relocation_targets=None, max_accesses=128,
    known_static_cells=None,
):
    """Summarize memory-access base origins without emitting absolute addresses.

    Recognized origins are stack_pointer, adrp_derived_address,
    relocation_loaded_pointer, and unknown. State crosses only a unique
    forward CFG predecessor. Calls clobber modeled caller-saved registers;
    unknown instructions clear state. Conditional edges assume both outcomes.
    If known_static_cells is supplied, access ranges are compared against
    private eight-byte cells and only redacted boolean matches/counts are emitted.
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
    known_static_cells = _validate_known_static_cells(known_static_cells)

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
    outgoing_static_cell_value_origins = {}
    observations = []
    literal_load_observations = []
    total_literal_loads = sum(
        _decode_ldr_literal(word, start_va + index * 4) is not None
        for index, word in enumerate(words)
    )
    reachable_literal_loads = 0
    relocation_backed_literal_loads = 0
    total_accesses = sum(
        decode_integer_immediate_memory_access(word) is not None
        for word in words
    )
    reachable_accesses = 0
    known_provenance_accesses = 0
    known_static_cell_match_count = 0
    known_static_cell_load_match_count = 0
    known_static_cell_store_match_count = 0
    known_static_cell_full_width_load_match_count = 0
    known_static_cell_derived_base_access_count = 0

    for block_index, (block_start, block_end) in enumerate(blocks):
        if block_index not in reachable:
            continue
        incoming = predecessors[block_index]
        if block_index == 0 or len(incoming) != 1:
            registers = {}
            static_cell_value_origins = {}
        else:
            predecessor = next(iter(incoming))
            if (blocks[predecessor][0] < block_start
                    and predecessor in outgoing_states):
                registers = dict(outgoing_states[predecessor])
                static_cell_value_origins = dict(
                    outgoing_static_cell_value_origins[predecessor]
                )
            else:
                registers = {}
                static_cell_value_origins = {}

        for instruction_index in range(block_start, block_end):
            word = words[instruction_index]
            pc = start_va + instruction_index * 4

            adr = _decode_adr(word, pc)
            if adr is not None:
                destination, address = adr
                if destination != 31:
                    registers[destination] = (
                        "adr_derived_address", address, instruction_index, 1
                    )
                    static_cell_value_origins.pop(destination, None)
                continue

            adrp = _decode_adrp(word, pc)
            if adrp is not None:
                destination, address = adrp
                if destination != 31:
                    registers[destination] = (
                        "adrp_derived_address", address, instruction_index, 1
                    )
                    static_cell_value_origins.pop(destination, None)
                continue

            add_from_sp = _decode_add_from_stack_pointer(word)
            if add_from_sp is not None:
                destination, _immediate = add_from_sp
                # The concrete SP value is intentionally not modeled. Preserve
                # only its provenance class so it cannot be mistaken for an
                # absolute address or used for relocation-slot matching.
                registers[destination] = (
                    "stack_pointer", None, instruction_index, 1
                )
                static_cell_value_origins.pop(destination, None)
                continue

            sub = _decode_sub_immediate(word)
            if sub is not None:
                destination, source, immediate = sub
                if destination == 31:
                    # Writes to SP/XZR are outside the tracked general-register state.
                    continue
                source_has_static_cell_origin = (
                    static_cell_value_origins.get(source, False)
                )
                if source == 31:
                    registers[destination] = (
                        "stack_pointer", None, instruction_index, 1
                    )
                elif source in registers:
                    kind, value, _definition, depth = registers[source]
                    result = None if value is None else value - immediate
                    if result is None or result >= 0:
                        registers[destination] = (
                            kind, result, instruction_index, depth + 1
                        )
                    else:
                        registers.pop(destination, None)
                else:
                    registers.pop(destination, None)
                if source != 31 and source_has_static_cell_origin:
                    static_cell_value_origins[destination] = True
                else:
                    static_cell_value_origins.pop(destination, None)
                continue

            add = _decode_add_immediate(word)
            if add is not None:
                destination, source, immediate, width_mask = add
                source_has_static_cell_origin = (
                    static_cell_value_origins.get(source, False)
                )
                if width_mask == _U64_MAX and source in registers:
                    kind, value, _definition, depth = registers[source]
                    result = None if value is None else value + immediate
                    if result is None or result <= _U64_MAX:
                        registers[destination] = (
                            kind, result, instruction_index, depth + 1
                        )
                    else:
                        registers.pop(destination, None)
                else:
                    registers.pop(destination, None)
                if width_mask == _U64_MAX and source_has_static_cell_origin:
                    static_cell_value_origins[destination] = True
                else:
                    static_cell_value_origins.pop(destination, None)
                continue

            move = _decode_move_register(word)
            if move is not None:
                destination, source, width_mask = move
                if destination != 31:
                    source_has_static_cell_origin = (
                        static_cell_value_origins.get(source, False)
                    )
                    if width_mask == _U64_MAX and source in registers:
                        kind, value, definition, depth = registers[source]
                        registers[destination] = (
                            kind, value, definition, depth + 1
                        )
                    else:
                        registers.pop(destination, None)
                    if width_mask == _U64_MAX and source_has_static_cell_origin:
                        static_cell_value_origins[destination] = True
                    else:
                        static_cell_value_origins.pop(destination, None)
                continue

            literal_load = _decode_ldr_literal(word, pc)
            if literal_load is not None:
                destination, literal_slot = literal_load
                relocation_target = relocations.get(literal_slot)
                reachable_literal_loads += 1
                if relocation_target is not None:
                    relocation_backed_literal_loads += 1
                if len(literal_load_observations) < max_accesses:
                    literal_load_observations.append({
                        "instruction_index": instruction_index,
                        "target_register": "xzr" if destination == 31 else f"x{destination}",
                        "source": "pc_relative_literal",
                        "relocation_backed": relocation_target is not None,
                    })
                if destination != 31:
                    if relocation_target is None:
                        registers.pop(destination, None)
                    else:
                        registers[destination] = (
                            "relocation_loaded_pointer",
                            relocation_target,
                            instruction_index,
                            1,
                        )
                    static_cell_value_origins.pop(destination, None)
                continue

            access = decode_integer_immediate_memory_access(word)
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
                base_derived_from_known_static_cell = (
                    base != 31 and static_cell_value_origins.get(base, False)
                )
                reachable_accesses += 1
                if provenance != "unknown":
                    known_provenance_accesses += 1
                if known_static_cells is not None and base_derived_from_known_static_cell:
                    known_static_cell_derived_base_access_count += 1
                matches_known_static_cell = None
                if known_static_cells is not None:
                    matches_known_static_cell = _memory_access_overlaps_known_static_cell(
                        base_state, access, known_static_cells
                    )
                    if matches_known_static_cell:
                        known_static_cell_match_count += 1
                        if access["operation"] == "load":
                            known_static_cell_load_match_count += 1
                        elif access["operation"] == "store":
                            known_static_cell_store_match_count += 1
                if len(observations) < max_accesses:
                    observation = {
                        "instruction_index": instruction_index,
                        "operation": access["operation"],
                        "access_bytes": access["access_bytes"],
                        "base_register": access["base_register"],
                        "addressing_mode": access["addressing_mode"],
                        "byte_offset": access["byte_offset"],
                        "base_update_bytes": access["base_update_bytes"],
                        "base_provenance": provenance,
                        "base_definition_instruction_index": definition,
                        "base_derivation_depth": depth,
                    }
                    if known_static_cells is not None:
                        observation["matches_known_static_cell"] = matches_known_static_cell
                        observation["base_derived_from_known_static_cell"] = (
                            base_derived_from_known_static_cell
                        )
                    observations.append(observation)

                if access["operation"] == "load" and target != 31:
                    registers.pop(target, None)
                    exact_static_cell_load = (
                        known_static_cells is not None
                        and _load_exactly_matches_known_static_cell(
                            base_state, access, known_static_cells
                        )
                    )
                    if exact_static_cell_load:
                        known_static_cell_full_width_load_match_count += 1
                        static_cell_value_origins[target] = True
                    else:
                        static_cell_value_origins.pop(target, None)
                    if (access["access_bytes"] == 8 and base_state is not None
                            and base_state[1] is not None):
                        effective_address = base_state[1] + access["byte_offset"]
                        if 0 <= effective_address <= _U64_MAX:
                            relocated_target = relocations.get(effective_address)
                            if relocated_target is not None:
                                registers[target] = (
                                    "relocation_loaded_pointer",
                                    relocated_target,
                                    instruction_index,
                                    1,
                                )

                # Pre/post-indexed forms update the base after the memory
                # operation. Preserve only a previously known symbolic origin.
                writeback = access["base_update_bytes"]
                if writeback and base != 31:
                    if base_state is None:
                        registers.pop(base, None)
                    else:
                        kind, value, _definition, depth = base_state
                        updated_value = None if value is None else value + writeback
                        if (updated_value is None
                                or 0 <= updated_value <= _U64_MAX):
                            registers[base] = (
                                kind, updated_value, instruction_index, depth + 1
                            )
                        else:
                            registers.pop(base, None)
                continue

            if (_decode_bl_target(word, pc) is not None
                    or _is_indirect_call(word)):
                for register in _CALLER_SAVED_REGISTERS:
                    registers.pop(register, None)
                    static_cell_value_origins.pop(register, None)
                continue

            if (_decode_conditional_branch_target(word, pc) is not None
                    or _decode_unconditional_branch_target(word, pc) is not None
                    or _is_indirect_branch(word)
                    or word == _NOP):
                continue

            registers.clear()
            static_cell_value_origins.clear()

        outgoing_states[block_index] = registers
        outgoing_static_cell_value_origins[block_index] = (
            static_cell_value_origins
        )

    result = {
        "analysis_kind": "bounded_cfg_memory_base_provenance",
        "instruction_count": instruction_count,
        "literal_load_count": total_literal_loads,
        "statically_reachable_literal_load_count": reachable_literal_loads,
        "statically_unreachable_literal_load_count": total_literal_loads - reachable_literal_loads,
        "relocation_backed_literal_load_count": relocation_backed_literal_loads,
        "literal_loads": literal_load_observations,
        "literal_loads_truncated": reachable_literal_loads > len(literal_load_observations),
        "memory_access_count": total_accesses,
        "statically_reachable_memory_access_count": reachable_accesses,
        "statically_unreachable_memory_access_count": total_accesses - reachable_accesses,
        "memory_accesses_with_known_base_provenance": known_provenance_accesses,
        "memory_accesses": observations,
        "memory_accesses_truncated": reachable_accesses > len(observations),
        "absolute_addresses_emitted": False,
        "raw_instructions_emitted": False,
    }
    if known_static_cells is not None:
        result["known_static_cell_match_count"] = known_static_cell_match_count
        result["known_static_cell_load_match_count"] = known_static_cell_load_match_count
        result["known_static_cell_store_match_count"] = known_static_cell_store_match_count
        result["known_static_cell_full_width_load_match_count"] = (
            known_static_cell_full_width_load_match_count
        )
        result["known_static_cell_derived_base_access_count"] = (
            known_static_cell_derived_base_access_count
        )
    return result
