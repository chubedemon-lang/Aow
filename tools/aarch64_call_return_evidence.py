"""Conservative evidence for immediate AArch64 call-result zero/bit tests.

A call followed immediately by CBZ/CBNZ or TBZ/TBNZ on W0/X0, or by
CMP W0/X0, #0 followed immediately by B.EQ/B.NE, is reported as a
register-dependency candidate only. Under AAPCS64 X0/W0 carries scalar
return values, but these structural observations do not prove the callee's
managed return type, semantics, runtime execution, or any AOW protocol meaning.
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


def _decode_tbz_tbnz_on_x0(word):
    """Decode TBZ/TBNZ W0 or X0; return bit and relative branch metadata."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0x7E000000) != 0x36000000 or (word & 0x1F) != 0:
        return None
    is_64_bit = bool(word & 0x80000000)
    tested_bit = (((word >> 31) & 1) << 5) | ((word >> 19) & 0x1F)
    if tested_bit >= (64 if is_64_bit else 32):
        return None
    return {
        "tested_register": "x0" if is_64_bit else "w0",
        "tested_bit": tested_bit,
        "branch_when": "nonzero" if word & (1 << 24) else "zero",
        "branch_target_delta_instructions": _sign_extend(
            (word >> 5) & 0x3FFF, 14
        ),
    }


def _decode_cmp_zero_on_x0(word):
    """Recognize only CMP W0, #0 and CMP X0, #0 (SUBS to the zero register)."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if word == 0x7100001F:
        return "w0"
    if word == 0xF100001F:
        return "x0"
    return None


def _decode_b_cond_eq_ne(word):
    """Decode B.EQ/B.NE and expose only its signed relative instruction delta."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    if (word & 0xFF000010) != 0x54000000:
        return None
    condition = word & 0xF
    if condition not in (0, 1):
        return None
    return {
        "branch_when": "zero" if condition == 0 else "nonzero",
        "branch_target_delta_instructions": _sign_extend(
            (word >> 5) & 0x7FFFF, 19
        ),
    }


def summarize_immediate_call_result_zero_tests(code, *, max_observations=128):
    """Report bounded call-result zero/bit-test candidates in one method window.

    Supported shapes are:
      * BL/BLR; CBZ/CBNZ W0/X0
      * BL/BLR; TBZ/TBNZ W0/X0, #bit
      * BL/BLR; CMP W0/X0, #0; B.EQ/B.NE

    The scan is linear and bounded. It does not follow branches, resolve call
    targets, infer return types, or evaluate conditions. Each recognized test
    is adjacent to the call or its compare/branch pair is adjacent, so no
    intervening instruction can overwrite the result register or flags.
    Other data-flow shapes remain unresolved.
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
    bit_test_count = 0
    cmp_branch_count = 0
    observations = []
    bit_test_observations = []
    cmp_branch_observations = []

    for index, word in enumerate(words):
        if _is_direct_call(word):
            call_kind = "direct_bl"
        elif _is_indirect_call(word):
            call_kind = "indirect_blr"
        else:
            continue
        call_count += 1

        branch_index = index + 1
        if branch_index < len(words):
            decoded = _decode_cbz_cbnz_on_x0(words[branch_index])
            if decoded is not None:
                matched_count += 1
                target_index = (
                    branch_index + decoded["branch_target_delta_instructions"]
                )
                if len(observations) < max_observations:
                    observations.append({
                        "call_instruction_index": index,
                        "branch_instruction_index": branch_index,
                        "call_kind": call_kind,
                        **decoded,
                        "branch_target_within_window": (
                            0 <= target_index < len(words)
                        ),
                        "branch_target_instruction_index": (
                            target_index if 0 <= target_index < len(words) else None
                        ),
                    })
                continue

            bit_test = _decode_tbz_tbnz_on_x0(words[branch_index])
            if bit_test is not None:
                bit_test_count += 1
                target_index = (
                    branch_index
                    + bit_test["branch_target_delta_instructions"]
                )
                if len(bit_test_observations) < max_observations:
                    bit_test_observations.append({
                        "call_instruction_index": index,
                        "branch_instruction_index": branch_index,
                        "call_kind": call_kind,
                        **bit_test,
                        "branch_target_within_window": (
                            0 <= target_index < len(words)
                        ),
                        "branch_target_instruction_index": (
                            target_index if 0 <= target_index < len(words) else None
                        ),
                    })
                continue

        compare_index = index + 1
        compare_register = (
            _decode_cmp_zero_on_x0(words[compare_index])
            if compare_index < len(words) else None
        )
        conditional_branch_index = index + 2
        decoded_branch = (
            _decode_b_cond_eq_ne(words[conditional_branch_index])
            if conditional_branch_index < len(words) else None
        )
        if compare_register is None or decoded_branch is None:
            continue

        cmp_branch_count += 1
        target_index = (
            conditional_branch_index
            + decoded_branch["branch_target_delta_instructions"]
        )
        if len(cmp_branch_observations) < max_observations:
            cmp_branch_observations.append({
                "call_instruction_index": index,
                "compare_instruction_index": compare_index,
                "branch_instruction_index": conditional_branch_index,
                "call_kind": call_kind,
                "tested_register": compare_register,
                **decoded_branch,
                "branch_target_within_window": 0 <= target_index < len(words),
                "branch_target_instruction_index": (
                    target_index if 0 <= target_index < len(words) else None
                ),
            })

    return {
        # Preserve the original discriminator for existing report consumers.
        "analysis_kind": "immediate_call_result_zero_test_candidate",
        "analysis_extensions": ["tbz_tbnz_bit_test"],
        "instruction_count": len(words),
        "recognized_call_count": call_count,
        "immediate_w0_x0_zero_test_count": matched_count,
        "calls_without_immediate_w0_x0_zero_test": call_count - matched_count,
        "observations": observations,
        "observations_truncated": matched_count > len(observations),
        "immediate_w0_x0_bit_test_count": bit_test_count,
        "bit_test_observations": bit_test_observations,
        "bit_test_observations_truncated": (
            bit_test_count > len(bit_test_observations)
        ),
        "immediate_cmp_zero_bcond_count": cmp_branch_count,
        "cmp_zero_bcond_observations": cmp_branch_observations,
        "cmp_zero_bcond_observations_truncated": (
            cmp_branch_count > len(cmp_branch_observations)
        ),
        "calls_without_either_zero_test_shape": (
            call_count - matched_count - cmp_branch_count
        ),
        "calls_without_any_recognized_result_test": (
            call_count - matched_count - bit_test_count - cmp_branch_count
        ),
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
    }
