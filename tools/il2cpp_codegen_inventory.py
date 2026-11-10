"""Offline IL2CPP v31 codegen inventory for an authorized local APK.

Only aggregate counts are emitted. Native addresses, relocation values,
endpoints, packet payloads and proprietary assets are never included.
"""
import argparse
import bisect
import hashlib
import json
import struct
import zipfile
from collections import defaultdict
from pathlib import Path

METADATA_MEMBER = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
ARM64_IL2CPP_MEMBER = "lib/arm64-v8a/libil2cpp.so"
MAGIC = 0xFAB11BAF
VERSION = 31
R_AARCH64_RELATIVE = 1027
MAX_APK = 1024 * 1024 * 1024
MAX_METADATA = 64 * 1024 * 1024
MAX_ELF = 512 * 1024 * 1024
RELEVANT = {
    "ScriptsAssembly.dll", "ConvertedAssembly.dll",
    "NetworkBase.dll", "ResourceDispatcher.dll",
}


class CodegenInventoryError(ValueError):
    pass


def _slice(data, offset, size, label):
    if (type(offset) is not int or type(size) is not int or offset < 0
            or size < 0 or offset > len(data) or size > len(data) - offset):
        raise CodegenInventoryError(f"{label} is outside its file")
    return data[offset:offset + size]


def _table(data, pair_offset, stride, label):
    offset, size = struct.unpack_from("<II", data, pair_offset)
    if size % stride:
        raise CodegenInventoryError(f"{label} has a partial record")
    _slice(data, offset, size, label)
    return offset, size, size // stride


def _metadata_images(data):
    if len(data) < 0x100:
        raise CodegenInventoryError("metadata header is truncated")
    magic, version = struct.unpack_from("<II", data, 0)
    if magic != MAGIC or version != VERSION:
        raise CodegenInventoryError("expected IL2CPP metadata version 31")
    string_offset, string_size, _ = _table(data, 0x18, 1, "string heap")
    method_offset, method_size, method_total = _table(
        data, 0x30, 0x24, "method definitions"
    )
    type_offset, type_size, type_total = _table(
        data, 0xA0, 0x58, "type definitions"
    )
    image_offset, image_size, image_total = _table(
        data, 0xA8, 0x28, "image definitions"
    )
    strings = data[string_offset:string_offset + string_size]

    def read_string(index):
        if not 0 <= index < len(strings):
            raise CodegenInventoryError("image name index outside string heap")
        end = strings.find(b"\0", index)
        if end < 0:
            raise CodegenInventoryError("unterminated image name")
        try:
            return strings[index:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CodegenInventoryError("invalid UTF-8 image name") from exc

    images = []
    all_ranges = []
    for image_index in range(image_total):
        record = image_offset + image_index * 0x28
        values = struct.unpack_from("<10i", data, record)
        name_index, _assembly, type_start, type_count = values[:4]
        if (type_start < 0 or type_count < 0 or type_start > type_total
                or type_count > type_total - type_start):
            raise CodegenInventoryError("invalid image type range")
        name = read_string(name_index)
        intervals = []
        for type_index in range(type_start, type_start + type_count):
            record = type_offset + type_index * 0x58
            method_start = struct.unpack_from("<i", data, record + 0x24)[0]
            method_count = struct.unpack_from("<H", data, record + 0x40)[0]
            if not method_count:
                continue
            if (method_start < 0 or method_start > method_total
                    or method_count > method_total - method_start):
                raise CodegenInventoryError("invalid type method range")
            intervals.append((method_start, method_start + method_count))
        intervals.sort()
        if intervals:
            cursor = intervals[0][0]
            first = cursor
            for start, end in intervals:
                if start != cursor:
                    raise CodegenInventoryError(
                        f"overlapping or gapped method ranges in {name}"
                    )
                cursor = end
            count = cursor - first
            all_ranges.append((first, cursor, name))
        else:
            first, count = None, 0
        images.append({"name": name, "method_start": first, "method_count": count})

    all_ranges.sort()
    cursor = 0
    for start, end, name in all_ranges:
        if start != cursor:
            raise CodegenInventoryError(f"image method ranges overlap at {name}")
        cursor = end
    if cursor != method_total or sum(x["method_count"] for x in images) != method_total:
        raise CodegenInventoryError("image ranges do not cover method table")
    return {
        "version": version,
        "method_definitions": method_total,
        "image_count": image_total,
        "images": images,
    }


def _elf_sections(elf):
    if len(elf) < 64 or elf[:4] != b"\x7fELF":
        raise CodegenInventoryError("invalid or truncated ELF")
    ident = elf[:16]
    if ident[4:7] != b"\x02\x01\x01":
        raise CodegenInventoryError("expected ELF64 little-endian image")
    elf_type, machine = struct.unpack_from("<HH", elf, 16)
    if elf_type != 3 or machine != 183:
        raise CodegenInventoryError("expected AArch64 ET_DYN libil2cpp.so")
    section_offset = struct.unpack_from("<Q", elf, 40)[0]
    entry_size, count, names_index = struct.unpack_from("<HHH", elf, 58)
    if entry_size != 64 or not 1 <= count <= 4096 or names_index >= count:
        raise CodegenInventoryError("invalid ELF section table")
    table = _slice(elf, section_offset, entry_size * count, "section table")
    raw = [struct.unpack_from("<IIQQQQIIQQ", table, i * 64) for i in range(count)]
    names_record = raw[names_index]
    if names_record[1] != 3:
        raise CodegenInventoryError("invalid ELF section-name table")
    names = _slice(elf, names_record[4], names_record[5], "section-name table")
    sections = {}
    for item in raw:
        name_index, kind, flags, address, offset, size = item[:6]
        if kind != 8:
            _slice(elf, offset, size, "ELF section")
        if name_index >= len(names):
            raise CodegenInventoryError("invalid ELF section name offset")
        end = names.find(b"\0", name_index)
        if end < 0:
            raise CodegenInventoryError("unterminated ELF section name")
        name = names[name_index:end].decode("ascii", "replace")
        if name:
            if name in sections:
                raise CodegenInventoryError("duplicate ELF section")
            sections[name] = {
                "type": kind, "flags": flags, "address": address,
                "offset": offset, "size": size, "entry_size": item[9],
            }
    for required in (".rodata", ".data.rel.ro", ".rela.dyn"):
        if required not in sections:
            raise CodegenInventoryError(f"missing ELF section {required}")
    rela = sections[".rela.dyn"]
    if rela["type"] != 4 or rela["entry_size"] != 24 or rela["size"] % 24:
        raise CodegenInventoryError("unsupported ELF RELA table")

    relocations = {}
    by_addend = defaultdict(list)
    relative_offsets = []
    rela_data = _slice(elf, rela["offset"], rela["size"], ".rela.dyn")
    for index in range(rela["size"] // 24):
        offset, info, addend = struct.unpack_from("<QQq", rela_data, index * 24)
        kind = info & 0xFFFFFFFF
        if offset in relocations:
            raise CodegenInventoryError("duplicate relocation offset")
        relocations[offset] = (kind, addend)
        if kind == R_AARCH64_RELATIVE:
            by_addend[addend].append(offset)
            relative_offsets.append(offset)
    relative_offsets.sort()
    return sections, relocations, by_addend, relative_offsets


def _contains(section, address, size):
    return (
        type(address) is int and address >= section["address"] and size >= 0
        and address - section["address"] <= section["size"]
        and size <= section["size"] - (address - section["address"])
    )


def _match_modules(elf, images):
    sections, relocations, by_addend, relative_offsets = _elf_sections(elf)
    rodata = sections[".rodata"]
    relro = sections[".data.rel.ro"]
    ro = _slice(elf, rodata["offset"], rodata["size"], ".rodata")
    relro_data = _slice(elf, relro["offset"], relro["size"], ".data.rel.ro")
    writable = [
        s for s in sections.values()
        if s["type"] == 1 and (s["flags"] & 0x3) == 0x3
    ]
    executable = [
        s for s in sections.values()
        if s["type"] == 1 and (s["flags"] & 0x4)
    ]

    def is_executable(address):
        return any(
            s["address"] <= address < s["address"] + s["size"]
            for s in executable
        )

    matched, unmatched, mismatched = [], [], []
    for image in images:
        name = image["name"]
        needle = name.encode("utf-8") + b"\0"
        positions = []
        cursor = 0
        while True:
            position = ro.find(needle, cursor)
            if position < 0:
                break
            positions.append(position)
            cursor = position + 1

        candidates, count_mismatches = [], []
        for position in positions:
            name_address = rodata["address"] + position
            for module_address in by_addend.get(name_address, ()):
                if not _contains(relro, module_address, 24):
                    continue
                module_offset = module_address - relro["address"]
                native_count = struct.unpack_from("<I", relro_data, module_offset + 8)[0]
                if native_count != image["method_count"]:
                    count_mismatches.append(native_count)
                    continue
                pointer_relocation = relocations.get(module_address + 16)
                if native_count:
                    if (pointer_relocation is None
                            or pointer_relocation[0] != R_AARCH64_RELATIVE):
                        continue
                    pointer_table = pointer_relocation[1]
                    if not any(
                        _contains(s, pointer_table, native_count * 8)
                        for s in writable
                    ):
                        continue
                else:
                    pointer_table = (
                        pointer_relocation[1]
                        if pointer_relocation
                        and pointer_relocation[0] == R_AARCH64_RELATIVE
                        else 0
                    )
                candidates.append((pointer_table, native_count))

        if len(candidates) > 1:
            raise CodegenInventoryError(f"ambiguous codegen module: {name}")
        if not candidates:
            if count_mismatches:
                mismatched.append({
                    "name": name,
                    "metadata_method_count": image["method_count"],
                    "native_method_counts": sorted(set(count_mismatches)),
                })
            else:
                unmatched.append(name)
            continue

        pointer_table, pointer_count = candidates[0]
        first = bisect.bisect_left(relative_offsets, pointer_table)
        last = bisect.bisect_left(
            relative_offsets, pointer_table + pointer_count * 8
        ) if pointer_count else first
        relocated = last - first
        executable_targets = sum(
            is_executable(relocations[offset][1])
            for offset in relative_offsets[first:last]
        )
        matched.append({
            "name": name,
            "method_pointer_slots": pointer_count,
            "relocated_pointer_slots": relocated,
            "executable_pointer_targets": executable_targets,
        })
    return matched, unmatched, mismatched


def inspect_bytes(metadata, elf, apk_sha256=None):
    """Inspect in-memory metadata and arm64 libil2cpp bytes."""
    metadata_info = _metadata_images(metadata)
    matched, unmatched, mismatched = _match_modules(
        elf, metadata_info["images"]
    )
    return {
        "apk_sha256": apk_sha256,
        "metadata_version": metadata_info["version"],
        "elf_machine": "AArch64",
        "metadata_image_count": metadata_info["image_count"],
        "metadata_method_definitions": metadata_info["method_definitions"],
        "matched_codegen_modules": len(matched),
        "unmatched_images": unmatched,
        "mismatched_images": mismatched,
        "method_pointer_slots": sum(x["method_pointer_slots"] for x in matched),
        "relocated_method_pointer_slots": sum(
            x["relocated_pointer_slots"] for x in matched
        ),
        "relocated_targets_in_executable_sections": sum(
            x["executable_pointer_targets"] for x in matched
        ),
        "relevant_modules": [
            x for x in matched if x["name"] in RELEVANT
        ],
        "native_addresses_emitted": False,
        "interpretation": (
            "Exact metadata image names and equal method counts associate "
            "metadata method ranges with native codegen pointer tables. "
            "Relocation-backed slots are counted without emitting addresses. "
            "This is static registration evidence only, not a wire protocol, "
            "active transport, handshake, or compatibility proof."
        ),
    }


def inspect_apk(apk_path):
    """Read only metadata and arm64 libil2cpp from an authorized local APK."""
    path = Path(apk_path)
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_APK:
        raise CodegenInventoryError("APK path or size is invalid")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    try:
        with zipfile.ZipFile(path) as archive:
            metadata_info = archive.getinfo(METADATA_MEMBER)
            elf_info = archive.getinfo(ARM64_IL2CPP_MEMBER)
            if metadata_info.file_size > MAX_METADATA or elf_info.file_size > MAX_ELF:
                raise CodegenInventoryError("analysis member exceeds size limit")
            with archive.open(metadata_info) as member:
                metadata = member.read(MAX_METADATA + 1)
            with archive.open(elf_info) as member:
                elf = member.read(MAX_ELF + 1)
    except (KeyError, zipfile.BadZipFile, OSError) as exc:
        raise CodegenInventoryError("APK missing valid IL2CPP members") from exc
    if len(metadata) > MAX_METADATA or len(elf) > MAX_ELF:
        raise CodegenInventoryError("analysis member exceeds size limit")
    return inspect_bytes(metadata, elf, digest.hexdigest())


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline IL2CPP v31 codegen inventory; aggregate output only"
    )
    parser.add_argument("apk", help="path to an authorized local APK")
    parser.add_argument("--output", help="write JSON to a local file")
    args = parser.parse_args(argv)
    report = json.dumps(inspect_apk(args.apk), indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
