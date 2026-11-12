"""Conservative, redacted AArch64 small-immediate and register-move evidence.

This is a linear bounded-window analysis, not a control-flow graph or ABI
proof. It reports only small constants in x0-x7 immediately before uniquely
resolved, allowlisted direct calls. It never emits native addresses or bytes.
"""
import struct


_MAX_REPORTED_CONSTANT = 0xFFFF
_CALLER_SAVED_REGISTERS = frozenset(range(19)) | {30}
_NOP = 0xD503201F
_MAX_CODE_WINDOW_BYTES = 64 * 1024


def _decode_move_wide(word):
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    opcode = word & 0x7F800000
    if opcode not in (0x12800000, 0x52800000, 0x72800000):
        return None
    is_64 = bool(word & 0x80000000)
    shift = ((word >> 21) & 0x3) * 16
    if not is_64 and shift > 16:
        return None
    destination = word & 0x1F
    if destination == 31:
        return None
    immediate = (word >> 5) & 0xFFFF
    width_mask = (1 << (64 if is_64 else 32)) - 1
    if opcode == 0x52800000:  # MOVZ
        operation = "movz"
    elif opcode == 0x12800000:  # MOVN
        operation = "movn"
    else:
        operation = "movk"
    return operation, destination, immediate, shift, width_mask



def _decode_move_register(word):
    """Decode the unshifted MOV-register alias (ORR Xd, XZR, Xm)."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    # ORR (shifted register), with N=0, LSL #0 and Rn=31 (ZR).
    # Bit 31 (sf) is deliberately excluded so W and X forms share the mask.
    if (word & 0x7FE0FFE0) != 0x2A0003E0:
        return None
    destination = word & 0x1F
    source = (word >> 16) & 0x1F
    width_mask = (1 << (64 if word & 0x80000000 else 32)) - 1
    return destination, source, width_mask

def _decode_add_immediate(word):
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0x7F800000) != 0x11000000:  # ADD (immediate), W/X form
        return None
    is_64 = bool(word & 0x80000000)
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    if destination == 31 or source == 31:
        return None
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    width_mask = (1 << (64 if is_64 else 32)) - 1
    return destination, source, immediate, width_mask


def _decode_bl_target(word, pc):
    if (word & 0xFC000000) != 0x94000000:
        return None
    immediate = word & 0x03FFFFFF
    if immediate & 0x02000000:
        immediate -= 0x04000000
    return pc + (immediate << 2)


def _sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def _decode_conditional_branch_target(word, pc):
    """Decode B.cond, CBZ/CBNZ and TBZ/TBNZ targets."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None
    if (word & 0xFF000010) == 0x54000000:  # B.cond, signed imm19
        return pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2)
    if (word & 0x7E000000) == 0x34000000:  # CBZ/CBNZ, signed imm19
        return pc + (_sign_extend((word >> 5) & 0x7FFFF, 19) << 2)
    if (word & 0x7E000000) == 0x36000000:  # TBZ/TBNZ, signed imm14
        return pc + (_sign_extend((word >> 5) & 0x3FFF, 14) << 2)
    return None


def _decode_unconditional_branch_target(word, pc):
    """Decode the direct B-immediate target, excluding BL."""
    if (type(word) is not int or not 0 <= word <= 0xFFFFFFFF
            or type(pc) is not int or pc < 0 or pc % 4):
        return None
    if (word & 0xFC000000) != 0x14000000:
        return None
    return pc + (_sign_extend(word & 0x03FFFFFF, 26) << 2)


def _is_indirect_branch(word):
    # BR Xn and RET Xn. Register bits [9:5] are intentionally masked.
    return (word & 0xFFFFFC1F) in (0xD61F0000, 0xD65F0000)


def _is_indirect_call(word):
    # BLR Xn. It returns to the next instruction but clobbers caller-saved regs.
    return (word & 0xFFFFFC1F) == 0xD63F0000


def _build_control_flow_blocks(words, start_va):
    """Build a small intraprocedural CFG from supported AArch64 branches."""
    instruction_count = len(words)
    if not instruction_count:
        return [], []

    boundaries = {0}
    conditional_targets = {}
    unconditional_targets = {}
    indirect_terminators = set()

    for index, word in enumerate(words):
        pc = start_va + index * 4
        conditional_target = _decode_conditional_branch_target(word, pc)
        if conditional_target is not None:
            conditional_targets[index] = conditional_target
            target_offset = conditional_target - start_va
            if 0 <= target_offset < instruction_count * 4 and target_offset % 4 == 0:
                boundaries.add(target_offset // 4)
            if index + 1 < instruction_count:
                boundaries.add(index + 1)
            continue

        unconditional_target = _decode_unconditional_branch_target(word, pc)
        if unconditional_target is not None:
            unconditional_targets[index] = unconditional_target
            target_offset = unconditional_target - start_va
            if 0 <= target_offset < instruction_count * 4 and target_offset % 4 == 0:
                boundaries.add(target_offset // 4)
            if index + 1 < instruction_count:
                boundaries.add(index + 1)
            continue

        if _is_indirect_branch(word):
            indirect_terminators.add(index)
            if index + 1 < instruction_count:
                boundaries.add(index + 1)

    starts = sorted(boundaries)
    blocks = [
        (start, starts[position + 1] if position + 1 < len(starts)
         else instruction_count)
        for position, start in enumerate(starts)
    ]
    instruction_to_block = {}
    for block_index, (start, end) in enumerate(blocks):
        for instruction_index in range(start, end):
            instruction_to_block[instruction_index] = block_index

    successors = [set() for _ in blocks]
    for block_index, (start, end) in enumerate(blocks):
        last = end - 1
        if last in conditional_targets:
            target_offset = conditional_targets[last] - start_va
            target_index = target_offset // 4
            if (0 <= target_offset < instruction_count * 4
                    and target_offset % 4 == 0):
                successors[block_index].add(
                    instruction_to_block[target_index]
                )
            if end < instruction_count:
                successors[block_index].add(
                    instruction_to_block[end]
                )
        elif last in unconditional_targets:
            target_offset = unconditional_targets[last] - start_va
            target_index = target_offset // 4
            if (0 <= target_offset < instruction_count * 4
                    and target_offset % 4 == 0):
                successors[block_index].add(
                    instruction_to_block[target_index]
                )
        elif last in indirect_terminators:
            # An unresolved indirect branch or return exits this bounded CFG.
            pass
        elif end < instruction_count:
            successors[block_index].add(instruction_to_block[end])

    return blocks, successors


def summarize_small_argument_constants(
    code, start_va, method_targets, *, target_prefixes
):
    """Return conservative small constants at resolved allowlisted direct BL sites.

    A bounded intraprocedural CFG handles B.cond, CBZ/CBNZ, TBZ/TBNZ, B,
    BR and RET. Constants flow only across a unique forward predecessor;
    joins and backedges start with unknown register state. Unknown instructions
    clear the abstract state. BL/BLR calls clobber caller-saved registers.

    Only MOVZ/MOVN/MOVK, the unshifted MOV-register alias and ADD-immediate
    are modeled. Values above 0xffff are omitted. Output contains relative
    instruction/block indexes, never native addresses or instruction bytes.
    """
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if not isinstance(method_targets, dict):
        raise ValueError("method_targets must be a mapping")
    if (not isinstance(target_prefixes, (tuple, list, set, frozenset))
            or not target_prefixes
            or any(not isinstance(item, str) or not item for item in target_prefixes)):
        raise ValueError("target_prefixes must be a non-empty collection of strings")
    if not code:
        return []

    words = list(struct.unpack("<" + "I" * (len(code) // 4), code))
    blocks, successors = _build_control_flow_blocks(words, start_va)
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

    # Preserve the historical byte-order ordinal, including gaps for
    # unreachable direct calls. The new block/index fields make reachability
    # and the actual observation location explicit.
    call_ordinals = {}
    call_ordinal = 0
    for instruction_index, word in enumerate(words):
        if _decode_bl_target(word, start_va + instruction_index * 4) is not None:
            call_ordinals[instruction_index] = call_ordinal
            call_ordinal += 1

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
            if (blocks[predecessor][0] < block_start
                    and predecessor in outgoing_states):
                registers = dict(outgoing_states[predecessor])
            else:
                # Backedges are not iterated; dropping state is conservative.
                registers = {}

        for instruction_index in range(block_start, block_end):
            word = words[instruction_index]
            pc = start_va + instruction_index * 4

            move = _decode_move_wide(word)
            if move is not None:
                operation, destination, immediate, shift, width_mask = move
                if operation == "movz":
                    registers[destination] = (immediate << shift) & width_mask
                elif operation == "movn":
                    registers[destination] = (~(immediate << shift)) & width_mask
                elif destination in registers:
                    halfword_mask = 0xFFFF << shift
                    registers[destination] = (
                        (registers[destination] & ~halfword_mask)
                        | (immediate << shift)
                    ) & width_mask
                else:
                    registers.pop(destination, None)
                continue

            move_register = _decode_move_register(word)
            if move_register is not None:
                destination, source, width_mask = move_register
                if destination != 31:  # XZR/WZR destination discards the result.
                    if source == 31:  # XZR/WZR source is the known constant zero.
                        registers[destination] = 0
                    elif source in registers:
                        registers[destination] = registers[source] & width_mask
                    else:
                        registers.pop(destination, None)
                continue

            add = _decode_add_immediate(word)
            if add is not None:
                destination, source, immediate, width_mask = add
                if source in registers:
                    registers[destination] = (
                        registers[source] + immediate
                    ) & width_mask
                else:
                    registers.pop(destination, None)
                continue

            target = _decode_bl_target(word, pc)
            if target is not None:
                labels = method_targets.get(target, ())
                if isinstance(labels, (tuple, list, set, frozenset)):
                    unique_labels = sorted(set(
                        label for label in labels if isinstance(label, str)
                    ))
                else:
                    unique_labels = []
                if len(unique_labels) == 1:
                    label = unique_labels[0]
                    method_name = label.split("/p", 1)[0]
                    if any(method_name.endswith(prefix) for prefix in target_prefixes):
                        arguments = {
                            f"x{register}": registers[register]
                            for register in range(8)
                            if register in registers
                            and 0 <= registers[register] <= _MAX_REPORTED_CONSTANT
                        }
                        if arguments:
                            observations.append({
                                "linear_window_call_ordinal": call_ordinals[instruction_index],
                                "control_flow_block_index": block_index,
                                "instruction_index": instruction_index,
                                "target_method": method_name,
                                "known_small_argument_constants": arguments,
                            })
                for register in _CALLER_SAVED_REGISTERS:
                    registers.pop(register, None)
                continue

            if _is_indirect_call(word):
                for register in _CALLER_SAVED_REGISTERS:
                    registers.pop(register, None)
                continue

            if (_decode_conditional_branch_target(word, pc) is not None
                    or _decode_unconditional_branch_target(word, pc) is not None
                    or _is_indirect_branch(word)):
                continue

            if word != _NOP:
                registers.clear()

        outgoing_states[block_index] = registers

    return sorted(
        observations, key=lambda item: item["linear_window_call_ordinal"]
    )
