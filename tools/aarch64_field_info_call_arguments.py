"""Trace resolved static FieldInfo cells into direct-call argument registers.

This bounded offline AArch64 analysis correlates only exact 64-bit loads from
operator-supplied, relocation-backed FieldInfo usage cells with x0-x7 at a
uniquely resolved direct BL. It emits FieldRef coordinates, never addresses,
tokens, instructions, APK bytes, or packet data.

It is structural static evidence only. Both conditional outcomes are assumed;
joins, backedges, unknown instructions, calls, and unsupported transformations
drop provenance. CSEL retains a FieldRef coordinate only when both possible
inputs carry the same coordinate. MOVZ/MOVN/MOVK are modeled only for exact
instruction-immediate address construction; they do not establish relocation
or runtime identity. The pass does not prove execution, managed field identity,
packet-field identity, or wire semantics.
"""
import struct

from tools.aarch64_call_argument_evidence import (
    _CALLER_SAVED_REGISTERS,
    _build_control_flow_blocks,
    _decode_add_immediate,
    _decode_bl_target,
    _decode_conditional_branch_target,
    _decode_move_register,
    _decode_move_wide,
,    _decode_unconditional_branch_target,
    _is_indirect_branch,
    _is_indirect_call,
    _method_name_from_label,
    _ordered_method_labels,
)
from tools.aarch64_memory_access_evidence import decode_integer_memory_access
from tools.aarch64_memory_base_provenance import (
    _U64_MAX,
    _decode_adr,
    _decode_adrp,
    _decode_ldr_literal,
    _decode_sub_immediate,
    _validate_relocation_targets,
)

_MAX_CODE_WINDOW_BYTES = 64 * 1024
_MAX_FIELD_INFO_CELLS = 200_000
_MAX_METHOD_TARGETS = 200_000
_MAX_REPORTED_CALLS = 512
_NOP = 0xD503201F


def _decode_conditional_select(word):
    """Decode CSEL (not CSINC/CSINV/CSNEG), returning Rd, Rn, Rm, width mask."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    # sf is intentionally excluded; condition, Rm, Rn and Rd remain variable.
    # op[1:0] must be 00, which excludes the other conditional-select aliases.
    if (word & 0x7FE00C00) != 0x1A800000:
        return None
    destination = word & 0x1F
    source_n = (word >> 5) & 0x1F
    source_m = (word >> 16) & 0x1F
    width_mask = _U64_MAX if word & 0x80000000 else 0xFFFFFFFF
    return destination, source_n, source_m, width_mask


def _decode_conditional_select_transform(word):
    """Decode CSINC/CSINV/CSNEG, whose result is not a value-preserving copy."""
    if type(word) is not int or not 0 <= word <= 0xFFFFFFFF:
        return None
    family = word & 0x7FE00C00
    operation = {
        0x1A800400: "csinc",
        0x5A800000: "csinv",
        0x5A800400: "csneg",
    }.get(family)
    if operation is None:
        return None
    destination = word & 0x1F
    source_n = (word >> 5) & 0x1F
    source_m = (word >> 16) & 0x1F
    width_mask = _U64_MAX if word & 0x80000000 else 0xFFFFFFFF
    return destination, source_n, source_m, width_mask, operation


def _validate_field_info_cell_references(value):
    """Validate address -> (occurrence, FieldRef index, TypeIndex, local index)."""
    if type(value) is not dict:
        raise ValueError("field_info_cell_references must be an exact dict")
    if len(value) > _MAX_FIELD_INFO_CELLS:
        raise ValueError("FieldInfo cell map exceeds the analysis limit")
    result = {}
    for address, reference in value.items():
        if type(address) is not int or not 0 <= address <= _U64_MAX - 7:
            raise ValueError("FieldInfo cell addresses must be unsigned 64-bit ranges")
        if type(reference) is not tuple or len(reference) != 4:
            raise ValueError("FieldInfo cell references must be exact four-integer tuples")
        if any(
            type(item) is not int or item < 0 or item > 0x7FFFFFFF
            for item in reference
        ):
            raise ValueError("FieldInfo reference coordinates must be non-negative 31-bit integers")
        result[address] = reference
    return result


def _validate_method_targets(value):
    """Validate and detach the address -> metadata-label association map."""
    if type(value) is not dict:
        raise ValueError("method_targets must be an exact dict")
    if len(value) > _MAX_METHOD_TARGETS:
        raise ValueError("method target map exceeds the analysis limit")
    result = {}
    for address, labels in value.items():
        if (
            type(address) is not int
            or not 0 <= address <= _U64_MAX
            or address % 4
        ):
            raise ValueError("method target addresses must be aligned unsigned 64-bit integers")
        if type(labels) not in (list, tuple) or not labels:
            raise ValueError("method target labels must be non-empty built-in lists or tuples")
        copied_labels = tuple(labels)
        if any(_method_name_from_label(label) is None for label in copied_labels):
            raise ValueError("method target labels must use canonical metadata /pN suffixes")
        # Do not retain caller-owned lists or the mutable input dictionary.
        # A later mutation must not change which metadata method a direct BL
        # is attributed to during this analysis pass.
        result[address] = copied_labels
    return result


def _reference_report(reference):
    position, field_ref_index, type_index, local_field_index = reference
    return {
        "usage_occurrence_position": position,
        "field_ref_index": field_ref_index,
        "type_index": type_index,
        "field_index_within_type": local_field_index,
    }


def _indirect_call_input_registers(word):
    """Return BLR target/authentication input registers, not ABI arguments."""
    if (word & 0xFFFFFC1F) == 0xD63F0000:  # BLR Xn
        return frozenset({(word >> 5) & 0x1F})
    if (word & 0xFFFFFC00) in (0xD73F0800, 0xD73F0C00):  # BLRAA/BLRAB Xn, Xm
        return frozenset({(word >> 5) & 0x1F, word & 0x1F})
    if (word & 0xFFFFFC1F) in (0xD63F081F, 0xD63F0C1F):  # BLRAAZ/BLRABZ Xn
        return frozenset({(word >> 5) & 0x1F})
    return frozenset()


def _indirect_call_target_register(word):
    """Return the control-flow target register for a recognized BLR-family call."""
    if (word & 0xFFFFFC1F) == 0xD63F0000:  # BLR Xn
        return (word >> 5) & 0x1F
    if (word & 0xFFFFFC00) in (0xD73F0800, 0xD73F0C00):  # BLRAA/BLRAB Xn, Xm
        return (word >> 5) & 0x1F
    if (word & 0xFFFFFC1F) in (0xD63F081F, 0xD63F0C1F):  # BLRAAZ/BLRABZ Xn
        return (word >> 5) & 0x1F
    return None


def summarize_field_info_call_arguments(
    code,
    start_va,
    method_targets,
    field_info_cell_references,
    *,
    relocation_targets=None,
    max_observations=128,
):
    """Report FieldInfo-derived values present in x0-x7 at resolved direct BLs.

    A value is tracked only after an exact 64-bit load from a supplied static
    FieldInfo usage cell. An unshifted 64-bit MOV-register alias preserves the
    full value. A 32-bit MOV zero-extends a truncated value and is tracked
    separately rather than reported as exact FieldInfo provenance. Address
    formation is limited to ADR/ADRP, MOVZ/MOVN/MOVK immediate construction,
    64-bit ADD/SUB immediate, MOV-register, and relocation-backed LDR-literal.
    No arithmetic is applied
    to FieldInfo values. State crosses only a unique forward CFG predecessor.

    Method-target labels are validated into an immutable per-call snapshot so
    caller mutation cannot change direct-call attribution mid-analysis.
    """
    if type(code) is not bytes or len(code) % 4:
        raise ValueError("AArch64 code window must be exact bytes and word aligned")
    if len(code) > _MAX_CODE_WINDOW_BYTES:
        raise ValueError("AArch64 code window exceeds the 64 KiB analysis limit")
    if (
        type(start_va) is not int
        or not 0 <= start_va <= _U64_MAX
        or start_va % 4
    ):
        raise ValueError("start_va must be an aligned unsigned 64-bit address")
    if code and start_va > _U64_MAX - (len(code) - 4):
        raise ValueError("AArch64 code window exceeds the unsigned 64-bit address space")
    if (
        type(max_observations) is not int
        or not 1 <= max_observations <= _MAX_REPORTED_CALLS
    ):
        raise ValueError("max_observations must be an integer in range 1..512")

    targets = _validate_method_targets(method_targets)
    cells = _validate_field_info_cell_references(field_info_cell_references)
    relocations = _validate_relocation_targets(relocation_targets)

    instruction_count = len(code) // 4
    words = list(struct.unpack("<" + "I" * instruction_count, code)) if code else []
    blocks, successors = _build_control_flow_blocks(words, start_va)

    reachable = set()
    pending = [0] if blocks else []
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
    indirect_call_ordinals = {}
    total_direct_calls = 0
    total_indirect_calls = 0
    for index, word in enumerate(words):
        if _decode_bl_target(word, start_va + index * 4) is not None:
            call_ordinals[index] = total_direct_calls
            total_direct_calls += 1
        if _is_indirect_call(word):
            indirect_call_ordinals[index] = total_indirect_calls
            total_indirect_calls += 1

    outgoing_addresses = {}
    outgoing_field_refs = {}
    outgoing_truncated_field_refs = {}
    observations = []
    observation_count = 0
    reachable_direct_calls = 0
    field_info_argument_direct_call_count = 0
    field_info_truncated_argument_direct_call_count = 0
    reachable_indirect_calls = 0
    resolved_indirect_call_count = 0
    unresolved_indirect_call_count = 0
    ambiguous_indirect_call_count = 0
    field_info_argument_indirect_call_count = 0
    field_info_truncated_argument_indirect_call_count = 0
    field_info_argument_resolved_indirect_call_count = 0
    field_info_argument_unattributed_indirect_call_count = 0
    field_info_truncated_argument_resolved_indirect_call_count = 0
    field_info_truncated_argument_unattributed_indirect_call_count = 0
    indirect_call_observations = []
    indirect_call_observation_count = 0
    unattributed_direct_call_count = 0
    ambiguous_target_direct_call_count = 0
    unknown_instruction_field_info_drop_count = 0
    unknown_instruction_exact_field_info_register_drop_count = 0
    unknown_instruction_truncated_field_info_register_drop_count = 0
    conditional_select_field_info_merge_drop_count = 0
    conditional_select_exact_source_register_unmerged_count = 0
    conditional_select_truncated_source_register_unmerged_count = 0
    conditional_select_transform_operation_counts = {
        "csinc": 0,
        "csinv": 0,
        "csneg": 0,
    }
    conditional_select_transform_field_info_use_count = 0
    conditional_select_transform_exact_source_register_use_count = 0
    conditional_select_transform_truncated_source_register_use_count = 0
    conditional_select_transform_exact_destination_drop_count = 0
    conditional_select_transform_truncated_destination_drop_count = 0

    for block_index, (block_start, block_end) in enumerate(blocks):
        if block_index not in reachable:
            continue
        incoming = predecessors[block_index]
        if block_index == 0 or len(incoming) != 1:
            addresses = {}
            field_refs = {}
            truncated_field_refs = {}
        else:
            predecessor = next(iter(incoming))
            if (
                blocks[predecessor][0] < block_start
                and predecessor in outgoing_addresses
            ):
                addresses = dict(outgoing_addresses[predecessor])
                field_refs = dict(outgoing_field_refs[predecessor])
                truncated_field_refs = dict(
                    outgoing_truncated_field_refs[predecessor]
                )
            else:
                addresses = {}
                field_refs = {}
                truncated_field_refs = {}

        for instruction_index in range(block_start, block_end):
            word = words[instruction_index]
            pc = start_va + instruction_index * 4

            adr = _decode_adr(word, pc)
            if adr is not None:
                destination, address = adr
                if destination != 31:
                    addresses[destination] = (address, instruction_index)
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            adrp = _decode_adrp(word, pc)
            if adrp is not None:
                destination, address = adrp
                if destination != 31:
                    addresses[destination] = (address, instruction_index)
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            move_wide = _decode_move_wide(word)
            if move_wide is not None:
                operation, destination, immediate, shift, width_mask = move_wide
                if destination != 31:
                    if operation == "movz":
                        address = (immediate << shift) & width_mask
                        addresses[destination] = (address, instruction_index)
                    elif operation == "movn":
                        address = (~(immediate << shift)) & width_mask
                        addresses[destination] = (address, instruction_index)
                    else:  # MOVK replaces one 16-bit lane of the prior value.
                        source_state = addresses.get(destination)
                        if source_state is None:
                            addresses.pop(destination, None)
                        else:
                            lane_mask = 0xFFFF << shift
                            address = (
                                (source_state[0] & width_mask & ~lane_mask)
                                | (immediate << shift)
                            ) & width_mask
                            addresses[destination] = (address, instruction_index)
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            add = _decode_add_immediate(word)
            if add is not None:
                destination, source, immediate, width_mask = add
                if destination != 31:
                    source_state = addresses.get(source) if width_mask == _U64_MAX else None
                    if source_state is None:
                        addresses.pop(destination, None)
                    else:
                        address = source_state[0] + immediate
                        if address <= _U64_MAX:
                            addresses[destination] = (address, instruction_index)
                        else:
                            addresses.pop(destination, None)
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            sub = _decode_sub_immediate(word)
            if sub is not None:
                destination, source, immediate = sub
                if destination != 31:
                    source_state = addresses.get(source) if source != 31 else None
                    if source_state is None or source_state[0] < immediate:
                        addresses.pop(destination, None)
                    else:
                        addresses[destination] = (
                            source_state[0] - immediate,
                            instruction_index,
                        )
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            move = _decode_move_register(word)
            if move is not None:
                destination, source, width_mask = move
                if destination != 31:
                    # Capture source provenance before writing destination: MOV
                    # permits source and destination to be the same register.
                    source_field_ref = field_refs.get(source)
                    source_has_exact_field_ref = source in field_refs
                    source_truncated_field_ref = truncated_field_refs.get(source)
                    source_has_truncated_field_ref = source in truncated_field_refs

                    if width_mask == _U64_MAX and source in addresses:
                        addresses[destination] = (
                            addresses[source][0],
                            addresses[source][1],
                        )
                    else:
                        addresses.pop(destination, None)

                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                    if source_has_exact_field_ref:
                        if width_mask == _U64_MAX:
                            field_refs[destination] = source_field_ref
                        else:
                            # MOV Wd, Wm zero-extends the low 32 bits; it cannot
                            # preserve an exact 64-bit FieldInfo-cell value.
                            truncated_field_refs[destination] = source_field_ref
                    elif source_has_truncated_field_ref:
                        # A later MOV Xd, Xm cannot recover bits already lost
                        # by an earlier 32-bit write.
                        truncated_field_refs[destination] = source_truncated_field_ref
                continue

            conditional_select = _decode_conditional_select(word)
            if conditional_select is not None:
                destination, source_n, source_m, width_mask = conditional_select
                if destination != 31:
                    # Snapshot both inputs before clearing Rd: CSEL permits Rd
                    # to alias either source register.
                    source_registers = (source_n, source_m)
                    exact_sources = [
                        field_refs.get(register) if register != 31 else None
                        for register in source_registers
                    ]
                    truncated_sources = [
                        truncated_field_refs.get(register) if register != 31 else None
                        for register in source_registers
                    ]
                    selected_references = [
                        exact if exact is not None else truncated
                        for exact, truncated in zip(exact_sources, truncated_sources)
                    ]
                    source_addresses = [
                        addresses.get(register) if register != 31 else None
                        for register in source_registers
                    ]

                    addresses.pop(destination, None)
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)

                    if (
                        selected_references[0] is not None
                        and selected_references[0] == selected_references[1]
                    ):
                        same_coordinate = selected_references[0]
                        if (
                            width_mask == _U64_MAX
                            and all(reference is not None for reference in exact_sources)
                        ):
                            field_refs[destination] = same_coordinate
                        else:
                            # A W-form CSEL zero-extends a 32-bit result; a
                            # source already marked truncated cannot regain bits.
                            truncated_field_refs[destination] = same_coordinate
                    elif any(reference is not None for reference in selected_references):
                        conditional_select_field_info_merge_drop_count += 1
                        conditional_select_exact_source_register_unmerged_count += sum(
                            reference is not None for reference in exact_sources
                        )
                        conditional_select_truncated_source_register_unmerged_count += sum(
                            reference is not None for reference in truncated_sources
                        )

                    if (
                        width_mask == _U64_MAX
                        and source_addresses[0] is not None
                        and source_addresses[1] is not None
                        and source_addresses[0][0] == source_addresses[1][0]
                    ):
                        addresses[destination] = (
                            source_addresses[0][0],
                            instruction_index,
                        )
                continue

            conditional_transform = _decode_conditional_select_transform(word)
            if conditional_transform is not None:
                (
                    destination,
                    source_n,
                    source_m,
                    width_mask,
                    operation,
                ) = conditional_transform
                conditional_select_transform_operation_counts[operation] += 1
                source_registers = {
                    register
                    for register in (source_n, source_m)
                    if register != 31
                }
                exact_source_count = sum(
                    register in field_refs for register in source_registers
                )
                truncated_source_count = sum(
                    register in truncated_field_refs
                    for register in source_registers
                )
                if exact_source_count or truncated_source_count:
                    conditional_select_transform_field_info_use_count += 1
                    conditional_select_transform_exact_source_register_use_count += (
                        exact_source_count
                    )
                    conditional_select_transform_truncated_source_register_use_count += (
                        truncated_source_count
                    )

                if destination != 31:
                    if destination in field_refs:
                        conditional_select_transform_exact_destination_drop_count += 1
                    if destination in truncated_field_refs:
                        conditional_select_transform_truncated_destination_drop_count += 1
                    # CSINC/CSINV/CSNEG transform the selected value. The
                    # sources remain unchanged unless Rd aliases one of them;
                    # only the destination loses value/address provenance.
                    addresses.pop(destination, None)
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            literal_load = _decode_ldr_literal(word, pc)
            if literal_load is not None:
                destination, literal_slot = literal_load
                if destination != 31:
                    relocation_target = relocations.get(literal_slot)
                    if relocation_target is None:
                        addresses.pop(destination, None)
                    else:
                        addresses[destination] = (
                            relocation_target,
                            instruction_index,
                        )
                    field_refs.pop(destination, None)
                    truncated_field_refs.pop(destination, None)
                continue

            access = decode_integer_memory_access(word)
            if access is not None:
                base_register = (word >> 5) & 0x1F
                base_state = (
                    addresses.get(base_register)
                    if base_register != 31 else None
                )
                if access["operation"] == "load":
                    element_bytes = access.get(
                        "element_bytes", access["access_bytes"]
                    )
                    load_targets = [(word & 0x1F, 0)]
                    if access.get("access_count") == 2:
                        load_targets.append(((word >> 10) & 0x1F, element_bytes))
                    for destination, displacement in load_targets:
                        if destination == 31:
                            continue
                        addresses.pop(destination, None)
                        field_refs.pop(destination, None)
                        truncated_field_refs.pop(destination, None)
                        byte_offset = access.get("byte_offset")
                        if (
                            element_bytes == 8
                            and type(byte_offset) is int
                            and base_state is not None
                        ):
                            effective_address = (
                                base_state[0] + byte_offset + displacement
                            )
                            if 0 <= effective_address <= _U64_MAX - 7:
                                if effective_address in cells:
                                    field_refs[destination] = cells[effective_address]
                                elif effective_address in relocations:
                                    # A relocation-backed pointer slot can feed
                                    # a later BLR-family target register. Keep
                                    # this separate from FieldInfo value provenance.
                                    addresses[destination] = (
                                        relocations[effective_address],
                                        instruction_index,
                                    )
                writeback = access.get("base_update_bytes", 0)
                if writeback and base_register != 31:
                    if base_state is None:
                        addresses.pop(base_register, None)
                    else:
                        updated = base_state[0] + writeback
                        if 0 <= updated <= _U64_MAX:
                            addresses[base_register] = (updated, instruction_index)
                        else:
                            addresses.pop(base_register, None)
                continue

            direct_target = _decode_bl_target(word, pc)
            if direct_target is not None:
                reachable_direct_calls += 1
                arguments = {
                    f"x{register}": _reference_report(field_refs[register])
                    for register in range(8)
                    if register in field_refs
                }
                truncated_arguments = [
                    register for register in range(8)
                    if register in truncated_field_refs
                ]
                if truncated_arguments:
                    field_info_truncated_argument_direct_call_count += 1
                if arguments:
                    field_info_argument_direct_call_count += 1
                    labels = _ordered_method_labels(targets.get(direct_target, ()))
                    if len(labels) != 1:
                        unattributed_direct_call_count += 1
                        if len(labels) > 1:
                            ambiguous_target_direct_call_count += 1
                    else:
                        method_name = _method_name_from_label(labels[0])
                        if method_name is not None:
                            observation_count += 1
                            if len(observations) < max_observations:
                                observations.append({
                                    "linear_window_call_ordinal": call_ordinals[instruction_index],
                                    "control_flow_block_index": block_index,
                                    "instruction_index": instruction_index,
                                    "target_method": method_name,
                                    "field_info_arguments": arguments,
                                })
                        else:
                            unattributed_direct_call_count += 1
                for register in _CALLER_SAVED_REGISTERS:
                    addresses.pop(register, None)
                    field_refs.pop(register, None)
                    truncated_field_refs.pop(register, None)
                continue

            if _is_indirect_call(word):
                reachable_indirect_calls += 1
                non_argument_inputs = _indirect_call_input_registers(word)
                target_register = _indirect_call_target_register(word)
                target_state = (
                    addresses.get(target_register)
                    if target_register is not None and target_register != 31
                    else None
                )
                target_address = target_state[0] if target_state is not None else None
                labels = _ordered_method_labels(targets.get(target_address, ()))
                target_method = (
                    _method_name_from_label(labels[0]) if len(labels) == 1 else None
                )
                if target_method is not None:
                    resolved_indirect_call_count += 1
                elif len(labels) > 1:
                    ambiguous_indirect_call_count += 1
                else:
                    unresolved_indirect_call_count += 1

                arguments = {
                    f"x{register}": _reference_report(field_refs[register])
                    for register in range(8)
                    if register not in non_argument_inputs and register in field_refs
                }
                truncated_arguments = [
                    register for register in range(8)
                    if register not in non_argument_inputs
                    and register in truncated_field_refs
                ]
                has_exact_field_argument = bool(arguments)
                has_truncated_field_argument = bool(truncated_arguments)
                if has_exact_field_argument:
                    field_info_argument_indirect_call_count += 1
                    if target_method is not None:
                        field_info_argument_resolved_indirect_call_count += 1
                    else:
                        field_info_argument_unattributed_indirect_call_count += 1
                if has_truncated_field_argument:
                    field_info_truncated_argument_indirect_call_count += 1
                    if target_method is not None:
                        field_info_truncated_argument_resolved_indirect_call_count += 1
                    else:
                        field_info_truncated_argument_unattributed_indirect_call_count += 1

                if target_method is not None and arguments:
                    indirect_call_observation_count += 1
                    if len(indirect_call_observations) < max_observations:
                        indirect_call_observations.append({
                            "linear_window_indirect_call_ordinal": (
                                indirect_call_ordinals[instruction_index]
                            ),
                            "control_flow_block_index": block_index,
                            "instruction_index": instruction_index,
                            "target_method": target_method,
                            "field_info_arguments": arguments,
                        })

                # The target and pointer-authentication modifier are instruction
                # inputs, not ABI arguments. Their registers are excluded above.
                # Indirect targets are attributed only when the tracked address
                # maps to one unique metadata-backed method entry.
                for register in _CALLER_SAVED_REGISTERS:
                    addresses.pop(register, None)
                    field_refs.pop(register, None)
                    truncated_field_refs.pop(register, None)
                continue

            if (
                _decode_conditional_branch_target(word, pc) is not None
                or _decode_unconditional_branch_target(word, pc) is not None
                or _is_indirect_branch(word)
                or word == _NOP
            ):
                continue

            # Unknown instructions may overwrite any tracked register. Count
            # FieldInfo provenance that is conservatively discarded so an
            # empty callsite summary can be distinguished from unsupported
            # data-flow encountered before the call.
            exact_dropped = len(field_refs)
            truncated_dropped = len(truncated_field_refs)
            if exact_dropped or truncated_dropped:
                unknown_instruction_field_info_drop_count += 1
                unknown_instruction_exact_field_info_register_drop_count += exact_dropped
                unknown_instruction_truncated_field_info_register_drop_count += truncated_dropped
            addresses.clear()
            field_refs.clear()
            truncated_field_refs.clear()

        outgoing_addresses[block_index] = addresses
        outgoing_field_refs[block_index] = field_refs
        outgoing_truncated_field_refs[block_index] = truncated_field_refs

    return {
        "analysis_kind": "bounded_cfg_field_info_call_argument_provenance",
        "field_info_cell_count": len(cells),
        "direct_call_instruction_count": total_direct_calls,
        "statically_reachable_direct_call_count": reachable_direct_calls,
        "field_info_argument_direct_call_count": field_info_argument_direct_call_count,
        "field_info_truncated_argument_direct_call_count": (
            field_info_truncated_argument_direct_call_count
        ),
        "indirect_call_instruction_count": total_indirect_calls,
        "statically_reachable_indirect_call_count": reachable_indirect_calls,
        "resolved_indirect_call_count": resolved_indirect_call_count,
        "unresolved_indirect_call_count": unresolved_indirect_call_count,
        "ambiguous_indirect_call_count": ambiguous_indirect_call_count,
        "field_info_argument_indirect_call_count": (
            field_info_argument_indirect_call_count
        ),
        "field_info_truncated_argument_indirect_call_count": (
            field_info_truncated_argument_indirect_call_count
        ),
        "field_info_argument_resolved_indirect_call_count": (
            field_info_argument_resolved_indirect_call_count
        ),
        "field_info_argument_unattributed_indirect_call_count": (
            field_info_argument_unattributed_indirect_call_count
        ),
        "field_info_truncated_argument_resolved_indirect_call_count": (
            field_info_truncated_argument_resolved_indirect_call_count
        ),
        "field_info_truncated_argument_unattributed_indirect_call_count": (
            field_info_truncated_argument_unattributed_indirect_call_count
        ),
        "indirect_call_observation_count": indirect_call_observation_count,
        "indirect_call_observations": indirect_call_observations,
        "indirect_call_observations_truncated": (
            indirect_call_observation_count > len(indirect_call_observations)
        ),
        "unattributed_direct_call_count": unattributed_direct_call_count,
        "ambiguous_target_direct_call_count": ambiguous_target_direct_call_count,
        "unknown_instruction_field_info_drop_count": (
            unknown_instruction_field_info_drop_count
        ),
        "unknown_instruction_exact_field_info_register_drop_count": (
            unknown_instruction_exact_field_info_register_drop_count
        ),
        "unknown_instruction_truncated_field_info_register_drop_count": (
            unknown_instruction_truncated_field_info_register_drop_count
        ),
        "conditional_select_field_info_merge_drop_count": (
            conditional_select_field_info_merge_drop_count
        ),
        "conditional_select_exact_source_register_unmerged_count": (
            conditional_select_exact_source_register_unmerged_count
        ),
        "conditional_select_truncated_source_register_unmerged_count": (
            conditional_select_truncated_source_register_unmerged_count
        ),
        "conditional_select_transform_operation_counts": (
            conditional_select_transform_operation_counts
        ),
        "conditional_select_transform_field_info_use_count": (
            conditional_select_transform_field_info_use_count
        ),
        "conditional_select_transform_exact_source_register_use_count": (
            conditional_select_transform_exact_source_register_use_count
        ),
        "conditional_select_transform_truncated_source_register_use_count": (
            conditional_select_transform_truncated_source_register_use_count
        ),
        "conditional_select_transform_exact_destination_drop_count": (
            conditional_select_transform_exact_destination_drop_count
        ),
        "conditional_select_transform_truncated_destination_drop_count": (
            conditional_select_transform_truncated_destination_drop_count
        ),
        "callsite_count": observation_count,
        "callsite_observations": observations,
        "callsite_observations_truncated": observation_count > len(observations),
        "absolute_addresses_emitted": False,
        "raw_instructions_emitted": False,
        "interpretation": (
            "A FieldRef coordinate is reported only when a value was loaded by "
            "an exact 64-bit integer load from a caller-supplied FieldInfo usage "
            "cell and remained in x0-x7 through value-preserving 64-bit MOV-register "
            "copies or a same-coordinate X-form CSEL until a uniquely resolved direct "
            "BL or BLR-family target. A CSEL coordinate is retained only when both "
            "possible inputs carry the same FieldRef coordinate; otherwise the "
            "destination is cleared and the unmerged source-register provenance is counted. "
            "CSINC, CSINV and CSNEG are recognized as value-transforming operations: "
            "tracked source use and destination drops are counted, only the destination "
            "register is cleared, and unrelated source registers remain tracked. "
            "Their transformed result is never promoted to exact FieldInfo provenance. "
            "32-bit MOV results, W-form CSEL results, and CSEL results with an already "
            "truncated input are tracked separately in the truncated-argument counters "
            "and are never emitted as exact FieldInfo provenance. Recognized BLR, "
            "BLRAA/BLRAB and zero-modifier authenticated indirect calls exclude "
            "their target and authentication-modifier registers from ABI arguments. "
            "An indirect target is resolved only when its tracked address maps to "
            "one unique metadata-backed method entry; relocation-backed literal "
            "and 64-bit pointer-slot loads can provide that address provenance. "
            "Resolved indirect calls carrying exact FieldInfo values receive a "
            "separate redacted per-call observation. Unresolved and ambiguous "
            "targets remain separate counters and are never attributed. Truncated "
            "FieldInfo values remain separately counted and are never emitted as "
            "exact coordinates. The report separately counts FieldInfo-bearing direct calls whose target is "
            "missing or ambiguous; those calls are not attributed or emitted as "
            "observations. Unknown instructions that conservatively clear tracked "
            "FieldInfo state are counted separately, including exact and truncated "
            "register drops; this exposes unsupported data-flow without treating it "
            "as a negative field-use result. This is "
            "static register provenance, not runtime execution, managed owner/name resolution, "
            "packet-field attribution, serializer order, or wire semantics. "
            "Both conditional outcomes are assumed; joins and backedges start unknown. "
            "Calls clobber caller-saved registers. Recognized CSINC/CSINV/CSNEG "
            "operations clear only their destination; other unknown instructions "
            "conservatively clear all tracked state."
        ),
    }
