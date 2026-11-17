"""Redacted AArch64 unsigned-immediate memory-access evidence.

The scanner reports only instruction-relative indexes, register names, access
widths and encoded byte offsets. It does not resolve the base register, identify
managed fields, build a control-flow graph, or establish runtime execution.
"""
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
