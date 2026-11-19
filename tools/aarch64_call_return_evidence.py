"""Conservative evidence for immediate AArch64 call-result zero tests.

A call followed immediately by CBZ/CBNZ on W0/X0 is reported as a register
dependency candidate only. Under AAPCS64 X0/W0 carries scalar return values,
but this structural observation does not prove the callee's managed return
type, semantics, runtime execution, or any AOW protocol meaning.
"""
from tools.aarch64_call_argument_evidence import _is_indirect_call

_MAX_CODE_WINDOW_BYTES = 64 * 1024
_MAX_REPORTED_OBSERVATIONS = 512


def _sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _is_direct_call(word):
    return type(word) is int and 0 <= word <= 0xFFFFFFFF and (
        word & 0xFC000000
    ) == 0x94000000


def _decode_cbz_cbnz_on_x0(word):
    """Decode CBZ/CBNZ W0 or X0; return only relative branch metadata."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0x7E000000) != 0x34000000 or (word & 0x1F) != 0:
        return None
    delta = _sign_extend((word >> 5) & 0x7FFFF, 19)
    return {
        "tested_register": "x0" if word & 0x80000000 else "w0",
        "branch_when": "nonzero" if word & (1 << 24) else "zero",
        "branch_target_delta_instructions": delta,
    }


def summarize_immediate_call_result_zero_tests(code, *, max_observations=128):
    """Report calls immediately followed by CBZ/CBNZ on the ABI result register.

    The scan is linear and bounded to one supplied method window. It does not
    follow branches, resolve call targets, infer return types, or evaluate
    conditions. Only the instruction immediately after a recognized BL/BLR
    (including pointer-authenticated BLR forms recognized by the shared
    decoder) is considered, so no intervening instruction can overwrite W0/X0.
    """
    if type(code) is not bytes:
        raise ValueError("AArch64 code window must be exact immutable bytes")
    if len(code) % 4:
        raise ValueError("AArch64 code window length must be a multiple of four")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if (type(max_observations) is not int
            or not 1 <= max_observations <= _MAX_REPORTED_OBSERVATIONS):
        raise ValueError("max_observations must be an integer in range 1..512")

    words = [
        int.from_bytes(code[index:index + 4], "little")
        for index in range(0, len(code), 4)
    ]
    call_count = 0
    matched_count = 0
    observations = []

    for index, word in enumerate(words):
        if _is_direct_call(word):
            call_kind = "direct_bl"
        elif _is_indirect_call(word):
            call_kind = "indirect_blr"
        else:
            continue
        call_count += 1
        branch_index = index + 1
        if branch_index >= len(words):
            continue
        decoded = _decode_cbz_cbnz_on_x0(words[branch_index])
        if decoded is None:
            continue
        matched_count += 1
        target_index = branch_index + decoded["branch_target_delta_instructions"]
        if len(observations) < max_observations:
            observations.append({
                "call_instruction_index": index,
                "branch_instruction_index": branch_index,
                "call_kind": call_kind,
                **decoded,
                "branch_target_within_window": 0 <= target_index < len(words),
                "branch_target_instruction_index": (
                    target_index if 0 <= target_index < len(words) else None
                ),
            })

    return {
        "analysis_kind": "immediate_call_result_zero_test_candidate",
        "instruction_count": len(words),
        "recognized_call_count": call_count,
        "immediate_w0_x0_zero_test_count": matched_count,
        "calls_without_immediate_w0_x0_zero_test": call_count - matched_count,
        "observations": observations,
        "observations_truncated": matched_count > len(observations),
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
    }
