"""Conservative, redacted AArch64 small-immediate and register-move evidence.

This is a linear bounded-window analysis, not a control-flow graph or ABI
proof. It reports only small constants in x0-x7 immediately before uniquely
resolved, allowlisted direct calls. It never emits native addresses or bytes.
"""
import struct


_MAX_REPORTED_CONSTANT = 0xFFFF
_CALLER_SAVED_REGISTERS = frozenset(range(19)) | {30}
_NOP = 0xD503201F


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


def summarize_small_argument_constants(
    code, start_va, method_targets, *, target_prefixes
):
    """Return small x0-x7 constants at selected uniquely resolved BL sites.

    The supported data-flow subset is MOVZ/MOVN/MOVK, the unshifted
    MOV-register alias, and ADD-immediate. Unknown instructions clear the
    abstract register state. Calls clear caller-saved registers. Unconditional
    branches clear all state because this pass does not follow control flow.
    Values above 0xffff are omitted so address-like or large constants are
    never published.
    """
    if not isinstance(code, bytes) or len(code) % 4:
        raise ValueError("AArch64 code window must be a multiple of four bytes")
    if type(start_va) is not int or start_va < 0 or start_va % 4:
        raise ValueError("AArch64 code window start must be an aligned address")
    if not isinstance(method_targets, dict):
        raise ValueError("method_targets must be a mapping")
    if (not isinstance(target_prefixes, (tuple, list, set, frozenset))
            or not target_prefixes
            or any(not isinstance(item, str) or not item for item in target_prefixes)):
        raise ValueError("target_prefixes must be a non-empty collection of strings")

    registers = {}
    observations = []
    call_ordinal = 0
    for offset in range(0, len(code), 4):
        word = struct.unpack_from("<I", code, offset)[0]
        pc = start_va + offset

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
                            "linear_window_call_ordinal": call_ordinal,
                            "target_method": method_name,
                            "known_small_argument_constants": arguments,
                        })
            call_ordinal += 1
            for register in _CALLER_SAVED_REGISTERS:
                registers.pop(register, None)
            continue

        if (word & 0xFC000000) == 0x14000000:  # B immediate
            registers.clear()
            continue
        if word != _NOP:
            registers.clear()

    return observations
