"""Synthetic instruction-vector tests for delegate target evidence only."""
import struct
import unittest

from tools.aarch64_delegate_target_evidence import (
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


if __name__ == "__main__":
    unittest.main()
