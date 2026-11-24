"""Conservative offline index for AArch64 ELF .eh_frame_hdr entries.

The returned window ends at the next FDE entry start in the same executable
section. It is an analysis window, not a claim about the exact function extent.
No native addresses are emitted by the CLI summary.
"""
import argparse
from bisect import bisect_left
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import struct

_MAX_ELF = 512 * 1024 * 1024
_MAX_FDE_COUNT = 1_000_000
_MAX_ADDRESS = (1 << 64) - 1
_ADDRESS_SPACE_END = 1 << 64
_EXPECTED_ENCODINGS = (1, 0x1B, 0x03, 0x3B)


class EhFrameIndexError(ValueError):
    """Malformed or unsupported AArch64 .eh_frame_hdr index."""


@dataclass(frozen=True)
class EhFrameEntry:
    start: int
    fde: int
    section_start: int
    section_end: int


@dataclass(frozen=True)
class EhFrameEntryWindow:
    start: int
    end: int
    fde: int

    @property
    def size_bytes(self):
        return self.end - self.start


def _range(value, name):
    if (type(value) not in (tuple, list) or len(value) != 2
            or type(value[0]) is not int or type(value[1]) is not int
            or value[0] < 0 or value[0] > _MAX_ADDRESS
            or value[1] <= value[0] or value[1] > _ADDRESS_SPACE_END):
        raise EhFrameIndexError(f"invalid {name} range")
    return value[0], value[1]


def _add_sdata4(base, displacement, name):
    """Apply one signed DW_EH_PE_sdata4 displacement in the ELF64 address space."""
    if type(base) is not int or not 0 <= base <= _MAX_ADDRESS:
        raise EhFrameIndexError(f"invalid {name} base")
    if type(displacement) is not int or not -(1 << 31) <= displacement < (1 << 31):
        raise EhFrameIndexError(f"invalid {name} displacement")
    result = base + displacement
    if not 0 <= result <= _MAX_ADDRESS:
        raise EhFrameIndexError(f"{name} address overflows ELF64")
    return result


def parse_eh_frame_header(data, header_address, eh_frame_range,
                          executable_ranges):
    """Parse the supported pcrel/datarel sdata4 GNU unwind header table.

    The supported encodings are version=1, eh_frame_ptr=pcrel|sdata4,
    fde_count=udata4 and table=datarel|sdata4. Every FDE pointer must land in
    .eh_frame and every initial PC must belong to exactly one executable
    section. Entries must be strictly sorted and unique.
    """
    if type(data) is not bytes:
        raise EhFrameIndexError("header must be exact bytes")
    if (type(header_address) is not int
            or not 0 <= header_address <= _MAX_ADDRESS - 4):
        raise EhFrameIndexError("invalid header address")
    frame_start, frame_end = _range(eh_frame_range, ".eh_frame")
    if type(executable_ranges) not in (tuple, list) or not executable_ranges:
        raise EhFrameIndexError("executable ranges are required")
    ranges = tuple(sorted(
        _range(item, "executable section") for item in executable_ranges
    ))
    if any(right[0] < left[1] for left, right in zip(ranges, ranges[1:])):
        raise EhFrameIndexError("executable section ranges overlap")
    if len(data) < 12:
        raise EhFrameIndexError(".eh_frame_hdr is truncated")
    if tuple(data[:4]) != _EXPECTED_ENCODINGS:
        raise EhFrameIndexError("unsupported .eh_frame_hdr encodings")

    frame_displacement = struct.unpack_from("<i", data, 4)[0]
    frame_pointer = _add_sdata4(
        header_address + 4, frame_displacement, "header .eh_frame pointer"
    )
    if not frame_start <= frame_pointer < frame_end:
        raise EhFrameIndexError("header .eh_frame pointer is out of range")

    count = struct.unpack_from("<I", data, 8)[0]
    if count > _MAX_FDE_COUNT:
        raise EhFrameIndexError("FDE count exceeds analysis limit")
    table_end = 12 + count * 8
    if table_end > len(data):
        raise EhFrameIndexError("FDE table is truncated")
    if any(data[table_end:]):
        raise EhFrameIndexError("non-zero bytes follow the FDE table")

    entries = []
    previous_start = -1
    seen_fdes = set()
    for index in range(count):
        offset = 12 + index * 8
        start_displacement, fde_displacement = struct.unpack_from(
            "<ii", data, offset
        )
        start = _add_sdata4(header_address, start_displacement, "FDE initial PC")
        fde = _add_sdata4(header_address, fde_displacement, "FDE pointer")
        if start <= previous_start or start % 4:
            raise EhFrameIndexError("FDE initial PCs are not strictly sorted")
        if fde % 4 or not frame_start <= fde < frame_end:
            raise EhFrameIndexError("FDE pointer is outside .eh_frame")
        if fde in seen_fdes:
            raise EhFrameIndexError("duplicate FDE pointer")
        matches = [(a, b) for a, b in ranges if a <= start < b]
        if len(matches) != 1:
            raise EhFrameIndexError(
                "FDE initial PC is outside or ambiguous across executable sections"
            )
        section_start, section_end = matches[0]
        entries.append(EhFrameEntry(start, fde, section_start, section_end))
        previous_start = start
        seen_fdes.add(fde)
    return tuple(entries)


def find_entry_window(entries, target):
    """Return a bounded window only when target exactly matches an FDE start.

    The exclusive end is the next FDE start in the same executable section,
    or that section's end for the final entry. This is deliberately not called
    the exact FDE function length.
    """
    if type(target) is not int or target < 0 or target % 4:
        raise EhFrameIndexError("target must be an aligned non-negative address")
    if type(entries) is not tuple or any(type(item) is not EhFrameEntry for item in entries):
        raise EhFrameIndexError("entries must be the parsed immutable tuple")
    starts = tuple(entry.start for entry in entries)
    index = bisect_left(starts, target)
    if index >= len(entries) or entries[index].start != target:
        return None
    current = entries[index]
    end = current.section_end
    if index + 1 < len(entries):
        following = entries[index + 1]
        if (following.section_start, following.section_end) == (
            current.section_start, current.section_end
        ):
            end = following.start
    if end <= current.start:
        raise EhFrameIndexError("empty FDE entry window")
    return EhFrameEntryWindow(current.start, end, current.fde)


def inspect_elf_targets(elf, targets):
    """Return redacted FDE-window coverage for requested private addresses."""
    if type(elf) is not bytes or not 0 < len(elf) <= _MAX_ELF:
        raise EhFrameIndexError("ELF bytes are invalid or exceed the size limit")
    if type(targets) not in (tuple, list) or len(targets) > 1024:
        raise EhFrameIndexError("targets must be a bounded sequence")
    from tools.il2cpp_codegen_inventory import _elf_sections, _slice

    try:
        sections, _, _, _ = _elf_sections(elf)
        header_section = sections[".eh_frame_hdr"]
        frame_section = sections[".eh_frame"]
        header = _slice(
            elf, header_section["offset"], header_section["size"], ".eh_frame_hdr"
        )
        executable = tuple(
            (section["address"], section["address"] + section["size"])
            for section in sections.values()
            if section["type"] == 1 and (section["flags"] & 0x4)
        )
    except (KeyError, ValueError) as exc:
        raise EhFrameIndexError("ELF lacks supported unwind sections") from exc

    entries = parse_eh_frame_header(
        header,
        header_section["address"],
        (
            frame_section["address"],
            frame_section["address"] + frame_section["size"],
        ),
        executable,
    )
    windows = [find_entry_window(entries, target) for target in targets]
    resolved = [window for window in windows if window is not None]
    return {
        "targets_requested": len(targets),
        "exact_fde_entry_targets": len(resolved),
        "unresolved_targets": len(windows) - len(resolved),
        "entry_window_bytes": sorted(window.size_bytes for window in resolved),
        "native_addresses_emitted": False,
        "raw_instructions_emitted": False,
        "interpretation": (
            "A target is resolved only when it exactly matches an .eh_frame_hdr "
            "initial-PC entry. Window size ends at the next FDE start in the "
            "same executable section, or at that section boundary. This is a "
            "bounded analysis window, not the exact function extent or a "
            "control-flow proof."
        ),
    }


def _same_file_snapshot(before, after):
    """Compare identity and mutation-sensitive metadata for one open file."""
    return all(
        getattr(before, name, None) == getattr(after, name, None)
        for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    )


def _read_regular_elf(path):
    """Read one stable regular file without following a symlink.

    O_NOFOLLOW is used where available. The lstat/fstat identity comparison
    provides a second check, and the bounded descriptor read detects growth,
    truncation, or metadata changes during the read.
    """
    path = Path(path)
    try:
        path_info = os.lstat(path)
    except OSError as exc:
        raise EhFrameIndexError("invalid or unsafe ELF path") from exc
    if not stat.S_ISREG(path_info.st_mode):
        raise EhFrameIndexError("ELF path must be a regular non-symlink file")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EhFrameIndexError("unable to open ELF without following links") from exc

    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino)
                != (path_info.st_dev, path_info.st_ino)):
            raise EhFrameIndexError("ELF path changed before open")
        if not 0 < opened.st_size <= _MAX_ELF:
            raise EhFrameIndexError("invalid or oversized ELF file")

        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise EhFrameIndexError("ELF file was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)

        if os.read(descriptor, 1):
            raise EhFrameIndexError("ELF file grew while reading")
        after = os.fstat(descriptor)
        if not _same_file_snapshot(opened, after):
            raise EhFrameIndexError("ELF file changed while reading")
        data = b"".join(chunks)
        if len(data) != opened.st_size:
            raise EhFrameIndexError("ELF file size changed while reading")
        return data
    except OSError as exc:
        raise EhFrameIndexError("unable to read stable ELF file") from exc
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Redacted offline AArch64 ELF FDE-entry index"
    )
    parser.add_argument("elf", help="private local AArch64 ELF path")
    parser.add_argument(
        "--target", action="append", required=True,
        help="private target address (decimal or 0x-prefixed); never emitted",
    )
    args = parser.parse_args(argv)
    try:
        targets = tuple(int(value, 0) for value in args.target)
    except ValueError as exc:
        raise SystemExit("invalid target address") from exc
    report = json.dumps(
        inspect_elf_targets(_read_regular_elf(args.elf), targets),
        indent=2, sort_keys=True,
    )
    print(report)


if __name__ == "__main__":
    main()
