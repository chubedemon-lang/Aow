"""Synthetic tests for the redacted AArch64 FDE-entry index."""
import struct
import unittest

from tools.aarch64_eh_frame_index import (
    EhFrameIndexError,
    find_entry_window,
    parse_eh_frame_header,
)


HEADER_ADDRESS = 0x1000
FRAME_RANGE = (0x2000, 0x3000)
EXECUTABLE_RANGES = ((0x4000, 0x5000), (0x6000, 0x7000))


def make_header(entries, *, encodings=(1, 0x1B, 0x03, 0x3B),
                header_address=HEADER_ADDRESS, frame_range=FRAME_RANGE,
                padding=0):
    output = bytearray(12 + len(entries) * 8 + padding)
    output[:4] = bytes(encodings)
    struct.pack_into("<iI", output, 4,
                     frame_range[0] - (header_address + 4), len(entries))
    for index, (start, fde) in enumerate(entries):
        struct.pack_into("<ii", output, 12 + index * 8,
                         start - header_address, fde - header_address)
    return bytes(output)


class Aarch64EhFrameIndexTests(unittest.TestCase):
    def test_parses_sorted_entries_and_returns_next_fde_window(self):
        data = make_header((
            (0x4100, 0x2100),
            (0x4180, 0x2140),
            (0x6FF0, 0x2180),
        ), padding=8)
        entries = parse_eh_frame_header(
            data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
        )
        first = find_entry_window(entries, 0x4100)
        self.assertEqual((first.start, first.end, first.fde), (
            0x4100, 0x4180, 0x2100
        ))
        self.assertEqual(first.size_bytes, 0x80)
        last = find_entry_window(entries, 0x6FF0)
        self.assertEqual((last.start, last.end, last.size_bytes), (
            0x6FF0, 0x7000, 0x10
        ))

    def test_unknown_target_is_not_rounded_to_nearest_entry(self):
        entries = parse_eh_frame_header(
            make_header(((0x4100, 0x2100),)),
            HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES,
        )
        self.assertIsNone(find_entry_window(entries, 0x4104))

    def test_rejects_boolean_or_unaligned_targets(self):
        entries = parse_eh_frame_header(
            make_header(((0x4100, 0x2100),)),
            HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES,
        )
        for target in (True, -4, 0x4102):
            with self.subTest(target=target), self.assertRaises(EhFrameIndexError):
                find_entry_window(entries, target)

    def test_rejects_custom_bytes_subclasses(self):
        class CustomBytes(bytes):
            pass
        with self.assertRaises(EhFrameIndexError):
            parse_eh_frame_header(
                CustomBytes(make_header(((0x4100, 0x2100),))),
                HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES,
            )

    def test_rejects_unsupported_encodings(self):
        data = make_header(((0x4100, 0x2100),), encodings=(1, 0x1B, 0x03, 0x1B))
        with self.assertRaisesRegex(EhFrameIndexError, "encodings"):
            parse_eh_frame_header(
                data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_truncated_header_and_table(self):
        with self.assertRaisesRegex(EhFrameIndexError, "truncated"):
            parse_eh_frame_header(
                b"\x01\x1b\x03", HEADER_ADDRESS,
                FRAME_RANGE, EXECUTABLE_RANGES,
            )
        data = make_header(((0x4100, 0x2100),))
        with self.assertRaisesRegex(EhFrameIndexError, "truncated"):
            parse_eh_frame_header(
                data[:19], HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_unsorted_or_duplicate_start_pcs(self):
        data = make_header(((0x4180, 0x2100), (0x4100, 0x2140)))
        with self.assertRaisesRegex(EhFrameIndexError, "sorted"):
            parse_eh_frame_header(
                data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_duplicate_fde_pointers(self):
        data = make_header(((0x4100, 0x2100), (0x4180, 0x2100)))
        with self.assertRaisesRegex(EhFrameIndexError, "duplicate FDE"):
            parse_eh_frame_header(
                data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_fde_outside_eh_frame(self):
        data = make_header(((0x4100, 0x3100),))
        with self.assertRaisesRegex(EhFrameIndexError, "outside .eh_frame"):
            parse_eh_frame_header(
                data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_pc_outside_executable_sections(self):
        data = make_header(((0x5100, 0x2100),))
        with self.assertRaisesRegex(EhFrameIndexError, "outside or ambiguous"):
            parse_eh_frame_header(
                data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_nonzero_trailing_data(self):
        data = make_header(((0x4100, 0x2100),), padding=1)
        data = data[:-1] + b"\x01"
        with self.assertRaisesRegex(EhFrameIndexError, "follow the FDE table"):
            parse_eh_frame_header(
                data, HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )

    def test_rejects_invalid_ranges_and_header_pointer(self):
        with self.assertRaises(EhFrameIndexError):
            parse_eh_frame_header(
                make_header(((0x4100, 0x2100),)),
                HEADER_ADDRESS, (0x3000, 0x2000), EXECUTABLE_RANGES,
            )
        data = bytearray(make_header(((0x4100, 0x2100),)))
        struct.pack_into("<i", data, 4, 0x7FFFFFFF)
        with self.assertRaisesRegex(EhFrameIndexError, "header .eh_frame pointer"):
            parse_eh_frame_header(
                bytes(data), HEADER_ADDRESS, FRAME_RANGE, EXECUTABLE_RANGES
            )


if __name__ == "__main__":
    unittest.main()
