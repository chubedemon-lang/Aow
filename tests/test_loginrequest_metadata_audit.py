"""Synthetic tests for the redacted IL2CPP v31 LoginRequest metadata audit."""
import hashlib
import os
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.loginrequest_metadata_audit import (
    LoginRequestMetadataError,
    inspect_apk,
    inspect_metadata_bytes,
)


def make_metadata(*, duplicate_request=False, invalid_field_range=False,
                  invalid_method_range=False, missing_serializer=False,
                  duplicate_field_names=False):
    data = bytearray(0x800)
    strings = bytearray()
    indexes = {}

    def add(value):
        if value not in indexes:
            indexes[value] = len(strings)
            strings.extend(value.encode("utf-8") + b"\0")
        return indexes[value]

    namespace = add("com.geargames.aow.messages")
    serializer_ns = add("com.geargames.serialization.serializers")
    request_name = add("LoginRequest")
    serializer_name = add("LoginRequestSTSerializer")
    deserializer_name = add("LoginRequestSTDeserializer")
    fields = [add("version"), add("buildNumber")]
    if duplicate_field_names:
        fields[1] = fields[0]
    methods = [add("get_Version"), add("serialize"), add(".ctor"),
               add("deserialize"), add(".ctor")]

    string_offset = 0x200
    method_offset = 0x300
    field_offset = 0x400
    type_offset = 0x500
    strings_end = string_offset + len(strings)
    data[string_offset:strings_end] = strings

    def pair(header, offset, size):
        struct.pack_into("<II", data, header, offset, size)

    pair(0x18, string_offset, len(strings))
    pair(0x30, method_offset, 5 * 0x24)
    pair(0x60, field_offset, 2 * 0x0C)
    type_count = 4 if duplicate_request else (2 if missing_serializer else 3)
    pair(0xA0, type_offset, type_count * 0x58)

    # Method records: name index at +0 and parameter count at +0x22.
    parameter_counts = (0, 4, 0, 3, 0)
    for i, (name_index, parameter_count) in enumerate(zip(methods, parameter_counts)):
        record = method_offset + i * 0x24
        struct.pack_into("<i", data, record, name_index)
        struct.pack_into("<H", data, record + 0x22, parameter_count)

    # Field records: name index, type index, custom-attribute index.
    for i, name_index in enumerate(fields):
        struct.pack_into("<iii", data, field_offset + i * 0x0C,
                         name_index, 100 + i, -1)

    def type_record(index, name_index, namespace_index, field_start,
                    method_start, method_count, field_count):
        record = type_offset + index * 0x58
        struct.pack_into("<ii", data, record, name_index, namespace_index)
        struct.pack_into("<i", data, record + 0x20,
                         99 if invalid_field_range and index == 0 else field_start)
        struct.pack_into("<i", data, record + 0x24,
                         99 if invalid_method_range and index == 0 else method_start)
        struct.pack_into("<H", data, record + 0x40, method_count)
        struct.pack_into("<H", data, record + 0x44, field_count)

    type_record(0, request_name, namespace, 0, 0, 1, 2)
    type_record(1, serializer_name, serializer_ns, 2, 1, 2, 0)
    if not missing_serializer:
        type_record(2, deserializer_name, serializer_ns, 2, 3, 2, 0)
    if duplicate_request:
        type_record(3, request_name, namespace, 0, 0, 1, 2)

    struct.pack_into("<II", data, 0, 0xFAB11BAF, 31)
    return bytes(data[:max(strings_end, type_offset + type_count * 0x58)])


class LoginRequestMetadataAuditTests(unittest.TestCase):
    def test_valid_metadata_returns_redacted_counts(self):
        report = inspect_metadata_bytes(make_metadata())
        self.assertEqual(report["metadata_version"], 31)
        self.assertEqual(report["login_request_metadata_field_count"], 2)
        self.assertEqual(report["login_request_unique_field_name_count"], 2)
        self.assertEqual(report["login_request_metadata_method_count"], 1)
        self.assertEqual(report["login_request_serializer_metadata_method_count"], 2)
        self.assertEqual(report["login_request_deserializer_metadata_method_count"], 2)
        self.assertEqual(report["serializer_metadata_parameter_count"], 4)
        self.assertEqual(report["deserializer_metadata_parameter_count"], 3)
        self.assertFalse(report["field_names_emitted"])
        self.assertFalse(report["field_type_indexes_emitted"])
        self.assertFalse(report["field_order_inferred"])
        self.assertFalse(report["wire_schema_verified"])

    def test_duplicate_field_names_are_counted_without_emitting_names(self):
        report = inspect_metadata_bytes(make_metadata(duplicate_field_names=True))
        self.assertEqual(report["login_request_metadata_field_count"], 2)
        self.assertEqual(report["login_request_unique_field_name_count"], 1)

    def test_rejects_non_bytes_and_wrong_metadata_version(self):
        with self.assertRaises(TypeError):
            inspect_metadata_bytes(bytearray(make_metadata()))
        malformed = bytearray(make_metadata())
        struct.pack_into("<I", malformed, 4, 30)
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(bytes(malformed))

    def test_rejects_truncated_header_and_out_of_bounds_tables(self):
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(b"short")
        malformed = bytearray(make_metadata())
        struct.pack_into("<II", malformed, 0x60, 0x7F0, 0x100)
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(bytes(malformed))

    def test_rejects_partial_field_records(self):
        malformed = bytearray(make_metadata())
        struct.pack_into("<II", malformed, 0x60, 0x400, 23)
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(bytes(malformed))

    def test_rejects_duplicate_target_type(self):
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(make_metadata(duplicate_request=True))

    def test_rejects_missing_serializer_pair(self):
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(make_metadata(missing_serializer=True))

    def test_rejects_field_range_outside_table(self):
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(make_metadata(invalid_field_range=True))

    def test_rejects_method_range_outside_table(self):
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(make_metadata(invalid_method_range=True))

    def test_rejects_negative_field_type_index(self):
        malformed = bytearray(make_metadata())
        struct.pack_into("<i", malformed, 0x400 + 4, -1)
        with self.assertRaises(LoginRequestMetadataError):
            inspect_metadata_bytes(bytes(malformed))

    def test_apk_reader_verifies_expected_fingerprint(self):
        metadata = make_metadata()
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                    metadata,
                )
            digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            report = inspect_apk(apk, digest)
            self.assertEqual(report["apk_sha256"], digest)
            self.assertEqual(report["login_request_metadata_field_count"], 2)
            with self.assertRaises(LoginRequestMetadataError):
                inspect_apk(apk, "0" * 64)

    def test_apk_reader_rejects_duplicate_metadata_member(self):
        metadata = make_metadata()
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "duplicate.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata
                )
                archive.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata
                )
            with self.assertRaises(LoginRequestMetadataError):
                inspect_apk(apk)

    def test_apk_reader_rejects_symlink_path(self):
        metadata = make_metadata()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.apk"
            link = Path(directory) / "link.apk"
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat", metadata
                )
            try:
                os.symlink(target, link)
            except (AttributeError, NotImplementedError, OSError):
                self.skipTest("symlinks are unavailable")
            with self.assertRaises(LoginRequestMetadataError):
                inspect_apk(link)


if __name__ == "__main__":
    unittest.main()
