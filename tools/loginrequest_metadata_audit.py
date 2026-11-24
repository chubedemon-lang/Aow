"""Redacted IL2CPP v31 metadata-shape audit for the AOW LoginRequest types.

This tool reads metadata only. It reports counts and validates table ranges;
it deliberately does not emit field names, field type indexes, field order,
wire IDs, native addresses, or packet semantics.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path


MAGIC = 0xFAB11BAF
VERSION = 31
STRING_PAIR_OFFSET = 0x18
METHOD_PAIR_OFFSET = 0x30
FIELD_PAIR_OFFSET = 0x60
TYPE_PAIR_OFFSET = 0xA0
METHOD_RECORD_SIZE = 0x24
FIELD_RECORD_SIZE = 0x0C
TYPE_RECORD_SIZE = 0x58

TARGET_NAMESPACE = "com.geargames.aow.messages"
TARGET_TYPE = "LoginRequest"
SERIALIZER_NAMESPACE = "com.geargames.serialization.serializers"
SERIALIZER_TYPE = "LoginRequestSTSerializer"
DESERIALIZER_TYPE = "LoginRequestSTDeserializer"


class LoginRequestMetadataError(ValueError):
    """Malformed or ambiguous IL2CPP metadata for the LoginRequest audit."""


def _table(data, pair_offset, record_size, label):
    if len(data) < pair_offset + 8:
        raise LoginRequestMetadataError("metadata header is truncated")
    offset = int.from_bytes(data[pair_offset:pair_offset + 4], "little")
    size = int.from_bytes(data[pair_offset + 4:pair_offset + 8], "little")
    if size % record_size:
        raise LoginRequestMetadataError(label + " table has a partial record")
    if offset > len(data) or size > len(data) - offset:
        raise LoginRequestMetadataError(label + " table is outside metadata")
    return offset, size // record_size


def _read_string(heap, index):
    if type(index) is not int or not 0 <= index < len(heap):
        raise LoginRequestMetadataError("string index is outside the metadata heap")
    end = heap.find(b"\0", index)
    if end < 0:
        raise LoginRequestMetadataError("metadata string is not terminated")
    try:
        return heap[index:end].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LoginRequestMetadataError("metadata string is not valid UTF-8") from exc


def _find_type(data, type_offset, type_count, heap, namespace, name):
    matches = []
    for index in range(type_count):
        record = type_offset + index * TYPE_RECORD_SIZE
        name_index = int.from_bytes(data[record:record + 4], "little", signed=True)
        namespace_index = int.from_bytes(
            data[record + 4:record + 8], "little", signed=True
        )
        type_name = _read_string(heap, name_index)
        type_namespace = _read_string(heap, namespace_index)
        if type_name == name and type_namespace == namespace:
            matches.append(record)
    if len(matches) != 1:
        raise LoginRequestMetadataError(
            "expected exactly one metadata type for " + name
        )
    return matches[0]


def _range_from_type(data, record, start_offset, count_offset, total, label):
    start = int.from_bytes(
        data[record + start_offset:record + start_offset + 4],
        "little", signed=True,
    )
    count = int.from_bytes(
        data[record + count_offset:record + count_offset + 2],
        "little",
    )
    if start < 0 or start > total or count > total - start:
        raise LoginRequestMetadataError(label + " range is outside its table")
    return start, count


def _method_summary(data, heap, method_offset, method_count, type_record,
                    expected_method, label):
    start, count = _range_from_type(
        data, type_record, 0x24, 0x40, method_count, label + " method"
    )
    names = []
    matching_parameter_counts = []
    for index in range(start, start + count):
        record = method_offset + index * METHOD_RECORD_SIZE
        name_index = int.from_bytes(
            data[record:record + 4], "little", signed=True
        )
        name = _read_string(heap, name_index)
        names.append(name)
        if name == expected_method:
            parameter_count = int.from_bytes(
                data[record0+0x22:record+0x24], "little"
            )
            matching_parameter_counts.append(parameter_count)
    if len(matching_parameter_counts) != 1:
        raise LoginRequestMetadataError(
            "expected exactly one " + expected_method + " metadata method"
        )
    return count, matching_parameter_counts[0]


def inspect_metadata_bytes(metadata):
    """Validate v31 LoginRequest metadata and return a redacted count summary."""
    if type(metadata) is not bytes:
        raise TypeError("metadata must be immutable bytes")
    if len(metadata) < 0xB0:
        raise LoginRequestMetadataError("metadata header is truncated")
    magic = int.from_bytes(metadata[0:4], "little")
    version = int.from_bytes(metadata[4:8], "little")
    if magic != MAGIC or version != VERSION:
        raise LoginRequestMetadataError("expected IL2CPP metadata version 31")

    string_offset, string_size = _table(metadata, STRING_PAIR_OFFSET, 1, "string")
    method_offset, method_count = _table(
        metadata, METHOD_PAIR_OFFSET, METHOD_RECORD_SIZE, "method"
    )
    field_offset, field_count = _table(
        metadata, FIELD_PAIR_OFFSET, FIELD_RECORD_SIZE, "field"
    )
    type_offset, type_count = _table(
        metadata, TYPE_PAIR_OFFSET, TYPE_RECORD_SIZE, "type"
    )
    heap = metadata[string_offset:string_offset + string_size]

    request_record = _find_type(
        metadata, type_offset, type_count, heap, TARGET_NAMESPACE, TARGET_TYPE
    )
    serializer_record = _find_type(
        metadata, type_offset, type_count, heap,
        SERIALIZER_NAMESPACE, SERIALIZER_TYPE,
    )
    deserializer_record = _find_type(
        metadata, type_offset, type_count, heap,
        SERIALIZER_NAMESPACE, DESERIALIZER_TYPE,
    )

    field_start, request_field_count = _range_from_type(
        metadata, request_record, 0x20, 0x44, field_count, "LoginRequest field"
    )
    field_names = set()
    for index in range(field_start, field_start + request_field_count):
        record = field_offset + index * FIELD_RECORD_SIZE
        name_index = int.from_bytes(
            metadata[record:record + 4], "little", signed=True
        )
        type_index = int.from_bytes(
            metadata[record + 4:record + 8], "little", signed=True
        )
        field_names.add(_read_string(heap, name_index))
        if type_index < 0:
            raise LoginRequestMetadataError("LoginRequest field has a negative type index")

    _request_method_start, request_method_count = _range_from_type(
        metadata, request_record, 0x24, 0x40, method_count,
        "LoginRequest method",
    )
    serializer_method_count, serialize_parameter_count = _method_summary(
        metadata, heap, method_offset, method_count,
        serializer_record, "serialize", "LoginRequest serializer",
    )
    deserializer_method_count, deserialize_parameter_count = _method_summary(
        metadata, heap, method_offset, method_count,
        deserializer_record, "deserialize", "LoginRequest deserializer",
    )

    return {
        "metadata_version": version,
        "login_request_metadata_field_count": request_field_count,
        "login_request_unique_field_name_count": len(field_names),
        "login_request_metadata_method_count": request_method_count,
        "login_request_serializer_metadata_method_count": serializer_method_count,
        "login_request_deserializer_metadata_method_count": deserializer_method_count,
        "serializer_metadata_parameter_count": serialize_parameter_count,
        "deserializer_metadata_parameter_count": deserialize_parameter_count,
        "field_names_emitted": False,
        "field_type_indexes_emitted": False,
        "field_order_inferred": False,
        "wire_schema_verified": False,
        "interpretation": (
            "Counts and table-range validation only. Metadata field order is not "
            "serializer execution order, method parameter counts are not payload "
            "field counts, and no LoginRequest wire schema or compatibility is inferred."
        ),
    }


def _read_apk_metadata(path):
    """Read metadata and fingerprint from one stable, no-follow APK descriptor."""
    path = Path(path)
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise LoginRequestMetadataError("invalid or inaccessible APK path") from exc
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 * 1024 * 1024:
        raise LoginRequestMetadataError("APK must be a bounded regular file")

    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LoginRequestMetadataError("unable to open APK safely") from exc

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or identity(before) != identity(opened):
            raise LoginRequestMetadataError("APK path changed before open")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            try:
                with zipfile.ZipFile(stream) as archive:
                    matches = [
                        item for item in archive.infolist()
                        if item.filename == "assets/bin/Data/Managed/Metadata/global-metadata.dat"
                    ]
                    if len(matches) != 1:
                        raise LoginRequestMetadataError(
                            "expected exactly one IL2CPP metadata member"
                        )
                    info = matches[0]
                    if info.flag_bits & 0x1 or info.file_size > 64 * 1024 * 1024:
                        raise LoginRequestMetadataError("metadata member is encrypted or oversized")
                    with archive.open(info) as member:
                        metadata = member.read(64 * 1024 * 1024 + 1)
                    if len(metadata) != info.file_size:
                        raise LoginRequestMetadataError("metadata member size mismatch")
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, OSError) as exc:
                if isinstance(exc, LoginRequestMetadataError):
                    raise
                raise LoginRequestMetadataError("APK is not a readable ZIP archive") from exc

            after_archive = os.fstat(stream.fileno())
            if identity(opened) != identity(after_archive):
                raise LoginRequestMetadataError("APK changed while reading metadata")
            stream.seek(0)
            digest = hashlib.sha256()
            total = 0
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                total += len(chunk)
                if total > opened.st_size:
                    raise LoginRequestMetadataError("APK grew while hashing")
                digest.update(chunk)
            after_hash = os.fstat(stream.fileno())
            if total != opened.st_size or identity(opened) != identity(after_hash):
                raise LoginRequestMetadataError("APK changed while hashing")
            try:
                path_after = os.lstat(path)
            except OSError as exc:
                raise LoginRequestMetadataError("APK path changed while reading") from exc
            if not stat.S_ISREG(path_after.st_mode) or identity(opened) != identity(path_after):
                raise LoginRequestMetadataError("APK path changed while reading")
            return metadata, digest.hexdigest()
    except OSError as exc:
        raise LoginRequestMetadataError("unable to read APK safely") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def inspect_apk(apk_path, expected_sha256=None):
    if expected_sha256 is not None and (
        type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
    ):
        raise ValueError("expected_sha256 must be 64 lowercase hexadecimal characters")
    metadata, digest = _read_apk_metadata(Path(apk_path))
    if expected_sha256 is not None and digest != expected_sha256:
        raise LoginRequestMetadataError("APK SHA-256 does not match expected fingerprint")
    report = inspect_metadata_bytes(metadata)
    report["apk_sha256"] = digest
    report["native_addresses_emitted"] = False
    report["raw_metadata_emitted"] = False
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Redacted offline IL2CPP v31 LoginRequest metadata-shape audit"
    )
    parser.add_argument("apk", help="path to an authorized local APK")
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
