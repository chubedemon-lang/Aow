"""Redacted IL2CPP v31 metadata-shape audit for AOW LoginRequest.

The report contains counts only. It never emits field names, type indexes,
native addresses, raw metadata, endpoints, or packet data.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import struct
import zipfile
from pathlib import Path

MAGIC = 0xFAB11BAF
VERSION = 31
STRING_PAIR = 0x18
METHOD_PAIR = 0x30
FIELD_PAIR = 0x60
TYPE_PAIR = 0xA0
METHOD_SIZE = 0x24
FIELD_SIZE = 0x0C
TYPE_SIZE = 0x58
METADATA_MEMBER = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
TARGET_NS = "com.geargames.aow.messages"
SERIALIZER_NS = "com.geargames.serialization.serializers"


class LoginRequestMetadataError(ValueError):
    """Malformed or ambiguous LoginRequest metadata."""


def _table(data, pair_offset, record_size, label):
    if len(data) < pair_offset + 8:
        raise LoginRequestMetadataError("truncated metadata header")
    offset, size = struct.unpack_from("<II", data, pair_offset)
    if size % record_size or offset > len(data) or size > len(data) - offset:
        raise LoginRequestMetadataError(label + " table is malformed or out of bounds")
    return offset, size // record_size


def _string(heap, index):
    if index < 0 or index >= len(heap):
        raise LoginRequestMetadataError("string index is out of bounds")
    end = heap.find(b"\0", index)
    if end < 0:
        raise LoginRequestMetadataError("unterminated metadata string")
    try:
        return heap[index:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LoginRequestMetadataError("invalid UTF-8 metadata string") from exc


def _find_type(data, offset, count, heap, namespace, name):
    matches = []
    for i in range(count):
        pos = offset + i * TYPE_SIZE
        name_index, namespace_index = struct.unpack_from("<ii", data, pos)
        if _string(heap, name_index) == name and _string(heap, namespace_index) == namespace:
            matches.append(pos)
    if len(matches) != 1:
        raise LoginRequestMetadataError("expected exactly one metadata type: " + name)
    return matches[0]


def _type_range(data, record, start_offset, count_offset, table_count, label):
    start = struct.unpack_from("<i", data, record + start_offset)[0]
    count = struct.unpack_from("<H", data, record + count_offset)[0]
    if start < 0 or start > table_count or count > table_count - start:
        raise LoginRequestMetadataError(label + " range is outside its table")
    return start, count


def _method_count_and_parameters(data, heap, method_offset, method_total,
                                 type_record, expected_name, label):
    start, count = _type_range(
        data, type_record, 0x24, 0x40, method_total, label + " method"
    )
    parameter_counts = []
    for i in range(start, start + count):
        pos = method_offset + i * METHOD_SIZE
        name_index = struct.unpack_from("<i", data, pos)[0]
        if _string(heap, name_index) == expected_name:
            parameter_counts.append(struct.unpack_from("<H", data, pos + 0x22)[0])
    if len(parameter_counts) != 1:
        raise LoginRequestMetadataError(
            "expected exactly one " + expected_name + " method in " + label
        )
    return count, parameter_counts[0]


def inspect_metadata_bytes(metadata):
    """Validate the v31 metadata ranges and return a redacted count summary."""
    if type(metadata) is not bytes:
        raise TypeError("metadata must be immutable bytes")
    if len(metadata) < 0xB0:
        raise LoginRequestMetadataError("truncated metadata header")
    magic, version = struct.unpack_from("<II", metadata, 0)
    if magic != MAGIC or version != VERSION:
        raise LoginRequestMetadataError("expected IL2CPP metadata version 31")

    string_offset, string_size = _table(metadata, STRING_PAIR, 1, "string")
    method_offset, method_total = _table(metadata, METHOD_PAIR, METHOD_SIZE, "method")
    field_offset, field_total = _table(metadata, FIELD_PAIR, FIELD_SIZE, "field")
    type_offset, type_total = _table(metadata, TYPE_PAIR, TYPE_SIZE, "type")
    heap = metadata[string_offset:string_offset + string_size]

    request = _find_type(
        metadata, type_offset, type_total, heap, TARGET_NS, "LoginRequest"
    )
    serializer = _find_type(
        metadata, type_offset, type_total, heap,
        SERIALIZER_NS, "LoginRequestSTSerializer",
    )
    deserializer = _find_type(
        metadata, type_offset, type_total, heap,
        SERIALIZER_NS, "LoginRequestSTDeserializer",
    )

    field_start, field_count = _type_range(
        metadata, request, 0x20, 0x44, field_total, "LoginRequest field"
    )
    field_names = set()
    for i in range(field_start, field_start + field_count):
        pos = field_offset + i * FIELD_SIZE
        name_index, type_index = struct.unpack_from("<ii", metadata, pos)
        field_names.add(_string(heap, name_index))
        if type_index < 0:
            raise LoginRequestMetadataError("negative LoginRequest field type index")

    _request_method_start, request_method_count = _type_range(
        metadata, request, 0x24, 0x40, method_total, "LoginRequest method"
    )
    serializer_methods, serializer_parameters = _method_count_and_parameters(
        metadata, heap, method_offset, method_total, serializer,
        "serialize", "LoginRequest serializer",
    )
    deserializer_methods, deserializer_parameters = _method_count_and_parameters(
        metadata, heap, method_offset, method_total, deserializer,
        "deserialize", "LoginRequest deserializer",
    )
    return {
        "metadata_version": version,
        "login_request_metadata_field_count": field_count,
        "login_request_unique_field_name_count": len(field_names),
        "login_request_metadata_method_count": request_method_count,
        "login_request_serializer_metadata_method_count": serializer_methods,
        "login_request_deserializer_metadata_method_count": deserializer_methods,
        "serializer_metadata_parameter_count": serializer_parameters,
        "deserializer_metadata_parameter_count": deserializer_parameters,
        "field_names_emitted": False,
        "field_type_indexes_emitted": False,
        "field_order_inferred": False,
        "wire_schema_verified": False,
        "interpretation": (
            "Metadata counts only. Field-table order is not serializer execution "
            "order; metadata parameter counts are not payload field counts. No "
            "wire schema, handshake, framing, or compatibility is inferred."
        ),
    }


def _read_apk_metadata(path):
    """Read one ZIP member and hash the same stable, no-follow APK descriptor."""
    path = Path(path)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise LoginRequestMetadataError("invalid or inaccessible APK path") from exc
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024**3:
        raise LoginRequestMetadataError("APK must be a bounded regular file")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise LoginRequestMetadataError("platform lacks no-follow file opening")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or identity(before) != identity(opened):
            raise LoginRequestMetadataError("APK changed before open")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            try:
                with zipfile.ZipFile(stream) as archive:
                    matches = [item for item in archive.infolist()
                               if item.filename == METADATA_MEMBER]
                    if len(matches) != 1:
                        raise LoginRequestMetadataError(
                            "expected exactly one IL2CPP metadata ZIP member"
                        )
                    info = matches[0]
                    if info.flag_bits & 1 or info.file_size > 64 * 1024 * 1024:
                        raise LoginRequestMetadataError("metadata member is encrypted or oversized")
                    with archive.open(info) as member:
                        metadata = member.read(64 * 1024 * 1024 + 1)
                    if len(metadata) != info.file_size:
                        raise LoginRequestMetadataError("metadata member size mismatch")
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, OSError) as exc:
                raise LoginRequestMetadataError("APK is not a readable ZIP archive") from exc

            if identity(opened) != identity(os.fstat(stream.fileno())):
                raise LoginRequestMetadataError("APK changed while reading metadata")
            stream.seek(0)
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                if total > opened.st_size:
                    raise LoginRequestMetadataError("APK grew while hashing")
                digest.update(chunk)
            if total != opened.st_size or identity(opened) != identity(os.fstat(stream.fileno())):
                raise LoginRequestMetadataError("APK changed while hashing")
            try:
                after = os.lstat(path)
            except OSError as exc:
                raise LoginRequestMetadataError("APK path changed while reading") from exc
            if not stat.S_ISREG(after.st_mode) or identity(opened) != identity(after):
                raise LoginRequestMetadataError("APK path changed while reading")
            return metadata, digest.hexdigest()
    finally:
        if descriptor is not None:
            os.close(descriptor)


def inspect_apk(apk_path, expected_sha256=None):
    if expected_sha256 is not None and (
        type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("expected_sha256 must be 64 lowercase hexadecimal characters")
    metadata, digest = _read_apk_metadata(apk_path)
    if expected_sha256 is not None and digest != expected_sha256:
        raise LoginRequestMetadataError("APK SHA-256 mismatch")
    report = inspect_metadata_bytes(metadata)
    report["apk_sha256"] = digest
    report["native_addresses_emitted"] = False
    report["raw_metadata_emitted"] = False
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Redacted offline IL2CPP v31 LoginRequest metadata audit"
    )
    parser.add_argument("apk", help="authorized local APK path")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    rendered = json.dumps(
        inspect_apk(args.apk, args.expected_sha256), indent=2, sort_keys=True
    ) + "\n"
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
