"""Synthetic instruction-vector tests for delegate target evidence only."""
import struct
import unittest

from tools.aarch64_delegate_target_evidence import (
    summarize_delegate_constructor_argument_shape,
    summarize_delegate_method_pointer_arguments,
)
from tools.il2cpp_codegen_inventory import R_AARCH64_RELATIVE


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def _encode_signed(value, bits):
    if not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise ValueError("immediate is out of range")
    return value & ((1 << bits) - 1)


def adr(register, pc, target):
    immediate = _encode_signed(target - pc, 21)
    immlo = immediate & 0x3
    immhi = immediate >> 2
    return 0x10000000 | (immlo << 29) | (immhi << 5) | register


def adrp(register, pc, target):
    pc_page = pc & ~0xFFF
    target_page = target & ~0xFFF
    delta = (target_page - pc_page) >> 12
    immediate = _encode_signed(delta, 21)
    immlo = immediate & 0x3
    immhi = immediate >> 2
    return 0x90000000 | (immlo << 29) | (immhi << 5) | register


def add_x(destination, source, immediate):
    return 0x91000000 | (immediate << 10) | (source << 5) | destination


def ldr_x(destination, base, byte_offset=0):
    if byte_offset % 8:
        raise ValueError("LDR X offset must be 8-byte aligned")
    return 0xF9400000 | ((byte_offset // 8) << 10) | (base << 5) | destination


def str_x(source, base, byte_offset=0):
    if byte_offset % 8:
        raise ValueError("STR X offset must be 8-byte aligned")
    return 0xF9000000 | ((byte_offset // 8) << 10) | (base << 5) | source


def mov_x(destination, source):
    return 0xAA0003E0 | (source << 16) | destination


def bl(pc, target):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    immediate = delta // 4
    if not -(1 << 25) <= immediate < (1 << 25):
        raise ValueError("BL target outside range")
    return 0x94000000 | (immediate & 0x03FFFFFF)


def b(pc, target):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x14000000 | ((delta // 4) & 0x03FFFFFF)


def b_cond(pc, target, condition=0):
    delta = target - pc
    if delta % 4:
        raise ValueError("unaligned branch target")
    return 0x54000000 | (((delta // 4) & 0x7FFFF) << 5) | condition


class DelegateTargetEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.start = 0x1000
        self.constructor = 0x4000
        self.callback = 0x6000
        self.constructor_label = (
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p2"
        )
        self.callback_label = (
            "com.geargames.unity.network.ConnectionReceiver::OnMessage/p1"
        )
        self.targets = {
            self.constructor: [self.constructor_label],
            self.callback: [self.callback_label],
        }

    def analyze(self, code, *, targets=None, relocations=None, start_va=None, **kwargs):
        return summarize_delegate_method_pointer_arguments(
            code,
            self.start if start_va is None else start_va,
            self.targets if targets is None else targets,
            {} if relocations is None else relocations,
            **kwargs,
        )

    def test_resolves_adr_materialized_method_pointer_in_x2(self):
        code = words(
            adr(9, self.start, self.callback),
            mov_x(2, 9),
            bl(self.start + 8, self.constructor),
        )
        result = self.analyze(code)
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {
                "resolution": "unique_metadata_method",
                "method": self.callback_label,
            },
        )

    def test_resolves_adrp_ldr_relocation_and_add_register_copy(self):
        pointer_slot = 0x9000
        code = words(
            adrp(8, self.start, pointer_slot),
            ldr_x(9, 8),
            add_x(10, 9, 0),
            mov_x(2, 10),
            bl(self.start + 16, self.constructor),
        )
        result = self.analyze(
            code,
            relocations={
                pointer_slot: (R_AARCH64_RELATIVE, self.callback),
            },
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"]["method"],
            self.callback_label,
        )

    def test_resolves_encoded_method_usage_from_static_data_cell(self):
        pointer_slot = 0x9000
        data_cell = 0xA000
        encoded_token = 0x60000000 | ((321 << 1) | 1)
        code = words(
            adrp(8, self.start, pointer_slot),
            ldr_x(8, 8, 0x6F0),
            ldr_x(2, 8),
            bl(self.start + 12, self.constructor),
        )
        result = self.analyze(
            code,
            relocations={
                pointer_slot + 0x6F0: (R_AARCH64_RELATIVE, data_cell),
            },
            static_memory_values={data_cell: encoded_token},
            encoded_method_usage_targets={
                encoded_token: [self.callback],
            },
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {
                "resolution": "unique_metadata_method",
                "method": self.callback_label,
                "via": "encoded_metadata_usage",
            },
        )

    def test_non_relative_cell_relocation_blocks_static_memory_fallback(self):
        pointer_slot = 0x9000
        data_cell = 0xA000
        encoded_token = 0x60000000 | ((321 << 1) | 1)
        code = words(
            adrp(8, self.start, pointer_slot),
            ldr_x(8, 8, 0x6F0),
            ldr_x(2, 8),
            bl(self.start + 12, self.constructor),
        )
        result = self.analyze(
            code,
            relocations={
                pointer_slot + 0x6F0: (R_AARCH64_RELATIVE, data_cell),
                data_cell: (1025, 0xB000),
            },
            static_memory_values={data_cell: encoded_token},
            encoded_method_usage_targets={
                encoded_token: [self.callback],
            },
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unknown"},
        )

    def test_ambiguous_encoded_method_usage_is_not_named(self):
        pointer_slot = 0x9000
        data_cell = 0xA000
        encoded_token = 0x60000000 | ((321 << 1) | 1)
        code = words(
            adrp(8, self.start, pointer_slot),
            ldr_x(8, 8, 0x6F0),
            ldr_x(2, 8),
            bl(self.start + 12, self.constructor),
        )
        result = self.analyze(
            code,
            relocations={
                pointer_slot + 0x6F0: (R_AARCH64_RELATIVE, data_cell),
            },
            static_memory_values={data_cell: encoded_token},
            encoded_method_usage_targets={
                encoded_token: [self.callback, 0x7000],
            },
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "ambiguous_metadata_method"},
        )

    def test_non_relative_or_missing_relocation_is_not_promoted(self):
        code = words(
            adrp(8, self.start, 0x9000),
            ldr_x(9, 8),
            mov_x(2, 9),
            bl(self.start + 12, self.constructor),
        )
        for relocation in (
            {},
            {0x9000: (1, self.callback)},
            {0x9000: (R_AARCH64_RELATIVE, -1)},
        ):
            with self.subTest(relocation=relocation):
                result = self.analyze(code, relocations=relocation)
                self.assertEqual(
                    result[0]["candidate_method_pointer_arguments"]["x2"],
                    {"resolution": "unknown"},
                )

    def test_rejects_malformed_method_target_address_keys(self):
        code = words(0xD503201F)
        for address in (True, -1, 1 << 64, "0x4000"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.analyze(
                    code,
                    targets={address: [self.constructor_label]},
                )

    def test_rejects_malformed_relocation_address_keys(self):
        code = words(0xD503201F)
        for address in (True, -1, 1 << 64, "0x9000"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.analyze(
                    code,
                    relocations={
                        address: (R_AARCH64_RELATIVE, self.callback),
                    },
                )

    def test_non_integer_relative_relocation_kind_is_not_accepted(self):
        pointer_slot = 0x9000
        code = words(
            adrp(8, self.start, pointer_slot),
            ldr_x(9, 8),
            mov_x(2, 9),
            bl(self.start + 12, self.constructor),
        )
        result = self.analyze(
            code,
            relocations={
                pointer_slot: (float(R_AARCH64_RELATIVE), self.callback),
            },
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unknown"},
        )

    def test_unknown_instruction_clears_pointer_state(self):
        code = words(
            adr(2, self.start, self.callback),
            0x8B010000,  # unsupported ADD-register form
            bl(self.start + 8, self.constructor),
        )
        result = self.analyze(code)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unknown"},
        )

    def test_call_clobbers_candidate_argument_register(self):
        helper = 0x4100
        targets = dict(self.targets)
        targets[helper] = ["com.geargames.common.network.Helper::Touch/p0"]
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, helper),
            bl(self.start + 8, self.constructor),
        )
        result = self.analyze(code, targets=targets)
        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unknown"},
        )

    def test_join_drops_path_specific_pointer_state(self):
        code = words(
            b_cond(self.start, self.start + 16),
            adr(9, self.start + 4, self.callback),
            mov_x(2, 9),
            b(self.start + 12, self.start + 20),
            0xD503201F,  # NOP on the other path
            bl(self.start + 20, self.constructor),
        )
        result = self.analyze(code)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unknown"},
        )

    def test_ambiguous_metadata_target_is_not_named(self):
        targets = dict(self.targets)
        targets[self.callback] = [
            self.callback_label,
            "com.geargames.common.network.OtherReceiver::OnMessage/p1",
        ]
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(code, targets=targets)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "ambiguous_metadata_method"},
        )

    def test_duplicate_identical_metadata_labels_remain_ambiguous(self):
        targets = dict(self.targets)
        targets[self.callback] = [self.callback_label, self.callback_label]
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(code, targets=targets)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "ambiguous_metadata_method"},
        )

    def test_unordered_callback_associations_are_not_promoted_to_unique(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        for associations in (
            {self.callback_label},
            frozenset((self.callback_label,)),
        ):
            with self.subTest(associations=associations):
                targets = dict(self.targets)
                targets[self.callback] = associations
                result = self.analyze(code, targets=targets)
                self.assertEqual(
                    result[0]["candidate_method_pointer_arguments"]["x2"],
                    {"resolution": "unresolved_metadata_method"},
                )

    def test_unordered_constructor_associations_are_not_accepted(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        for associations in (
            {self.constructor_label},
            frozenset((self.constructor_label,)),
        ):
            with self.subTest(associations=associations):
                targets = dict(self.targets)
                targets[self.constructor] = associations
                self.assertEqual(self.analyze(code, targets=targets), [])

    def test_malformed_method_arity_suffixes_are_not_resolved(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        malformed = (
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor",
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p",
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p2junk",
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p٢",
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p02",
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p65536",
            "com.geargames.common.network.OnMessageReceivedDelegate::.ctor/p2/p3",
        )
        for label in malformed:
            with self.subTest(label=label):
                targets = dict(self.targets)
                targets[self.constructor] = [label]
                self.assertEqual(self.analyze(code, targets=targets), [])

    def test_malformed_callback_arity_is_not_reported_as_unique(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        targets = dict(self.targets)
        targets[self.callback] = [
            "com.geargames.unity.network.ConnectionReceiver::OnMessage/p1extra"
        ]
        result = self.analyze(code, targets=targets)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unresolved_metadata_method"},
        )

    def test_constructor_allowlist_requires_a_type_name_boundary(self):
        targets = dict(self.targets)
        targets[self.constructor] = [
            "com.geargames.common.network.FakeOnMessageReceivedDelegate::.ctor/p2"
        ]
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        self.assertEqual(self.analyze(code, targets=targets), [])

    def test_malformed_constructor_association_is_not_treated_as_unique(self):
        targets = dict(self.targets)
        targets[self.constructor] = [self.constructor_label, None]
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        self.assertEqual(self.analyze(code, targets=targets), [])

    def test_malformed_callback_association_is_not_treated_as_unique(self):
        targets = dict(self.targets)
        targets[self.callback] = [self.callback_label, None]
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(code, targets=targets)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unresolved_metadata_method"},
        )

    def test_constructor_target_must_match_allowlist(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(
            code,
            target_prefixes=("UnrelatedDelegate::.ctor",),
        )
        self.assertEqual(result, [])

    def test_unreachable_constructor_call_is_not_reported(self):
        code = words(
            b(self.start, self.start + 8),
            bl(self.start + 4, self.constructor),
            bl(self.start + 8, self.constructor),
        )
        result = self.analyze(code)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["instruction_index"], 2)

    def test_report_never_contains_candidate_addresses_or_instruction_words(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(code)
        rendered = repr(result)
        self.assertNotIn(hex(self.callback), rendered)
        self.assertNotIn(hex(self.constructor), rendered)
        self.assertNotIn(str(self.callback), rendered)
        self.assertNotIn(str(self.constructor), rendered)
        self.assertNotIn("0x", rendered)

    def test_rejects_invalid_windows_mappings_and_registers(self):
        valid = words(0xD503201F)
        for code, start in ((b"abc", self.start), (b"\x00" * 4, self.start + 2)):
            with self.subTest(code=code, start=start), self.assertRaises(ValueError):
                self.analyze(code, **{"start_va": start})
        with self.assertRaises(ValueError):
            self.analyze(valid, relocations=[])
        with self.assertRaises(ValueError):
            self.analyze(valid, argument_registers=())
        for registers in ((True,), (8,), (2, 2), (2.0,)):
            with self.subTest(registers=registers), self.assertRaises(ValueError):
                self.analyze(valid, argument_registers=registers)
        with self.assertRaises(ValueError):
            self.analyze(valid, target_prefixes=())
        with self.assertRaises(ValueError):
            self.analyze(valid, static_memory_values={True: 1})
        with self.assertRaises(ValueError):
            self.analyze(valid, encoded_method_usage_targets={True: [self.callback]})


    def test_rejects_start_addresses_outside_unsigned_64_bit_space(self):
        valid = words(0xD503201F)
        for start in (True, -4, 1 << 64):
            with self.subTest(start=start), self.assertRaises(ValueError):
                self.analyze(valid, start_va=start)

    def test_rejects_code_window_that_wraps_unsigned_64_bit_space(self):
        # The first instruction fits at the highest aligned address, but the
        # second instruction would wrap the 64-bit virtual-address space.
        code = words(0xD503201F, 0xD503201F)
        with self.assertRaises(ValueError):
            self.analyze(code, start_va=0xFFFFFFFFFFFFFFFC)

    def test_accepts_code_window_ending_at_highest_aligned_address(self):
        code = words(0xD503201F, 0xD503201F)
        self.assertEqual(
            self.analyze(code, start_va=0xFFFFFFFFFFFFFFF8),
            [],
        )



    def test_constructor_argument_shape_reports_dereference_and_retention_without_offsets(self):
        code = words(
            0xF81D0FFE,  # prologue store
            0xA90157F6,  # saved registers
            0xA9024FF4,
            ldr_x(8, 2, 8),  # load a value through candidate x2
            mov_x(20, 2),
            mov_x(21, 1),
            mov_x(19, 0),
            str_x(2, 0, 0x28),  # retain original candidate on receiver
            str_x(8, 0, 0x10),  # retain dereferenced value on receiver
            0xF8020C01,  # unsupported pre-index store ends the bounded scan
        )
        result = summarize_delegate_constructor_argument_shape(code)
        self.assertEqual(
            result,
            {
                "argument_register": "x2",
                "receiver_register": "x0",
                "argument_pointer_dereferenced": True,
                "argument_pointer_retained_on_receiver": True,
                "dereferenced_value_retained_on_receiver": True,
                "straight_line_prefix_only": True,
            },
        )
        rendered = repr(result)
        self.assertNotIn("0x28", rendered)
        self.assertNotIn("0x10", rendered)
        self.assertNotIn("0xF940", rendered)

    def test_constructor_argument_shape_does_not_promote_unrelated_load(self):
        code = words(
            ldr_x(8, 3, 8),  # unrelated base, not the candidate argument
            str_x(2, 0, 0x28),
            str_x(8, 0, 0x10),
        )
        result = summarize_delegate_constructor_argument_shape(code)
        self.assertFalse(result["argument_pointer_dereferenced"])
        self.assertTrue(result["argument_pointer_retained_on_receiver"])
        self.assertFalse(result["dereferenced_value_retained_on_receiver"])

    def test_constructor_argument_shape_stops_at_unknown_after_dereference(self):
        code = words(
            ldr_x(8, 2, 8),
            0x8B090108,  # unsupported ADD-register form may overwrite x8
            str_x(8, 0, 0x10),
        )
        result = summarize_delegate_constructor_argument_shape(code)
        self.assertTrue(result["argument_pointer_dereferenced"])
        self.assertFalse(result["dereferenced_value_retained_on_receiver"])

    def test_constructor_argument_shape_rejects_invalid_inputs(self):
        with self.assertRaises(ValueError):
            summarize_delegate_constructor_argument_shape(b"abc")
        with self.assertRaises(ValueError):
            summarize_delegate_constructor_argument_shape(words(0xD503201F), argument_register=31)
        with self.assertRaises(ValueError):
            summarize_delegate_constructor_argument_shape(words(0xD503201F), receiver_register=True)
        with self.assertRaises(ValueError):
            summarize_delegate_constructor_argument_shape(words(0xD503201F), argument_register=0)


    def test_constructor_argument_shape_tracks_receiver_register_copies(self):
        code = words(
            mov_x(19, 0),  # receiver alias
            ldr_x(8, 2, 8),
            str_x(2, 19, 0x28),
            str_x(8, 19, 0x10),
        )
        result = summarize_delegate_constructor_argument_shape(code)
        self.assertTrue(result["argument_pointer_dereferenced"])
        self.assertTrue(result["argument_pointer_retained_on_receiver"])
        self.assertTrue(result["dereferenced_value_retained_on_receiver"])


    def test_constructor_argument_shape_stops_on_unknown_before_dereference(self):
        code = words(
            0x91000442,  # unsupported ADD X2, X2, #1 may overwrite candidate x2
            ldr_x(8, 2, 8),
            str_x(8, 0, 0x10),
        )
        result = summarize_delegate_constructor_argument_shape(code)
        self.assertFalse(result["argument_pointer_dereferenced"])
        self.assertFalse(result["dereferenced_value_retained_on_receiver"])

    def test_descriptor_pointer_resolves_only_through_supplied_metadata_mapping(self):
        descriptor = 0x7000
        code = words(
            adr(2, self.start, descriptor),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(
            code,
            descriptor_method_targets={descriptor: self.callback},
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {
                "resolution": "unique_metadata_method",
                "method": self.callback_label,
                "via": "descriptor_metadata",
            },
        )
        rendered = repr(result)
        self.assertNotIn(hex(descriptor), rendered)
        self.assertNotIn(hex(self.callback), rendered)

    def test_descriptor_mapping_preserves_duplicate_target_ambiguity(self):
        descriptor = 0x7000
        code = words(
            adr(2, self.start, descriptor),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(
            code,
            descriptor_method_targets={descriptor: (self.callback, self.callback)},
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "ambiguous_metadata_method"},
        )

    def test_descriptor_mapping_does_not_filter_malformed_targets(self):
        descriptor = 0x7000
        code = words(
            adr(2, self.start, descriptor),
            bl(self.start + 4, self.constructor),
        )
        for targets in (
            (self.callback, "invalid"),
            (self.callback, -1),
            (),
            {self.callback},
        ):
            with self.subTest(targets=targets):
                result = self.analyze(
                    code,
                    descriptor_method_targets={descriptor: targets},
                )
                self.assertEqual(
                    result[0]["candidate_method_pointer_arguments"]["x2"],
                    {"resolution": "unresolved_metadata_method"},
                )

    def test_descriptor_mapping_takes_precedence_over_direct_entry_match(self):
        # Even if an address appears in both maps, an explicit descriptor
        # association is authoritative and must not be bypassed on failure.
        descriptor = self.callback
        code = words(
            adr(2, self.start, descriptor),
            bl(self.start + 4, self.constructor),
        )
        result = self.analyze(
            code,
            descriptor_method_targets={descriptor: "invalid"},
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unresolved_metadata_method"},
        )

    def test_descriptor_mapping_must_be_a_mapping(self):
        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        with self.assertRaises(ValueError):
            self.analyze(code, descriptor_method_targets=[])

    def test_descriptor_mapping_rejects_non_integer_or_out_of_range_keys(self):
        code = words(
            adr(2, self.start, 0x7000),
            bl(self.start + 4, self.constructor),
        )
        for descriptor in (True, -1, 1 << 64, "0x7000"):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(ValueError):
                    self.analyze(
                        code,
                        descriptor_method_targets={descriptor: self.callback},
                    )



    def test_rejects_bytes_subclasses_before_custom_length_hooks(self):
        class HostileBytes(bytes):
            def __len__(self):
                raise AssertionError("custom bytes length must not run")

        payload = HostileBytes(words(0xD503201F))
        with self.assertRaisesRegex(ValueError, "code window"):
            self.analyze(payload)
        with self.assertRaisesRegex(ValueError, "code window"):
            summarize_delegate_constructor_argument_shape(payload)

    def test_rejects_mapping_subclasses_before_mapping_hooks(self):
        class HostileDict(dict):
            def __iter__(self):
                raise AssertionError("custom mapping iterator must not run")

            def items(self):
                raise AssertionError("custom mapping items must not run")

            def get(self, key, default=None):
                raise AssertionError("custom mapping lookup must not run")

        code = words(0xD503201F)
        cases = (
            {"targets": HostileDict(self.targets)},
            {"relocations": HostileDict()},
            {"descriptor_method_targets": HostileDict()},
            {"static_memory_values": HostileDict()},
            {"encoded_method_usage_targets": HostileDict()},
        )
        for kwargs in cases:
            with self.subTest(argument=next(iter(kwargs))), self.assertRaises(ValueError):
                self.analyze(code, **kwargs)

    def test_rejects_collection_subclasses_before_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom collection iterator must not run")

        code = words(0xD503201F)
        with self.assertRaises(ValueError):
            self.analyze(code, argument_registers=HostileList([2]))
        with self.assertRaises(ValueError):
            self.analyze(code, target_prefixes=HostileList(["OnMessageReceivedDelegate::.ctor"]))

    def test_rejects_hostile_metadata_label_without_calling_string_hooks(self):
        class HostileText(str):
            def rpartition(self, separator):
                raise AssertionError("custom rpartition must not run")

            def isascii(self):
                raise AssertionError("custom isascii must not run")

            def __lt__(self, other):
                raise AssertionError("custom ordering must not run")

        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        targets = dict(self.targets)
        targets[self.callback] = [HostileText(self.callback_label)]
        result = self.analyze(code, targets=targets)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unresolved_metadata_method"},
        )

        targets = dict(self.targets)
        targets[self.constructor] = [HostileText(self.constructor_label)]
        self.assertEqual(self.analyze(code, targets=targets), [])

    def test_rejects_metadata_association_list_subclass_without_iteration(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom association iterator must not run")

        code = words(
            adr(2, self.start, self.callback),
            bl(self.start + 4, self.constructor),
        )
        targets = dict(self.targets)
        targets[self.callback] = HostileList([self.callback_label])
        result = self.analyze(code, targets=targets)
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unresolved_metadata_method"},
        )

    def test_rejects_relocation_tuple_subclass_without_accessors(self):
        class HostileTuple(tuple):
            def __len__(self):
                raise AssertionError("custom relocation length must not run")

            def __getitem__(self, index):
                raise AssertionError("custom relocation indexing must not run")

        pointer_slot = 0x9000
        code = words(
            adrp(8, self.start, pointer_slot),
            ldr_x(9, 8),
            mov_x(2, 9),
            bl(self.start + 12, self.constructor),
        )
        result = self.analyze(
            code,
            relocations={
                pointer_slot: HostileTuple((R_AARCH64_RELATIVE, self.callback)),
            },
        )
        self.assertEqual(
            result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unknown"},
        )

    def test_rejects_descriptor_and_encoded_candidate_list_subclasses(self):
        class HostileList(list):
            def __iter__(self):
                raise AssertionError("custom candidate iterator must not run")

        descriptor = 0x7000
        code = words(
            adr(2, self.start, descriptor),
            bl(self.start + 4, self.constructor),
        )
        descriptor_result = self.analyze(
            code,
            descriptor_method_targets={descriptor: HostileList([self.callback])},
        )
        self.assertEqual(
            descriptor_result[0]["candidate_method_pointer_arguments"]["x2"],
            {"resolution": "unresolved_metadata_method"},
        )

        encoded_token = 0x60000000 | ((321 << 1) | 1)
        with self.assertRaisesRegex(ValueError, "executable address candidates"):
            self.analyze(
                words(0xD503201F),
                encoded_method_usage_targets={
                    encoded_token: HostileList([self.callback]),
                },
            )

if __name__ == "__main__":
    unittest.main()
