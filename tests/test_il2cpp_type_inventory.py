"""Synthetic-only tests for the IL2CPP v31 type-table inventory."""
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.il2cpp_metadata_inventory import METADATA_MAGIC, METADATA_MEMBER, MetadataInventoryError
from tools.il2cpp_type_inventory import inspect_type_tables


def make_metadata(types=(), *, version=31, magic=METADATA_MAGIC,
                  bad_type_size=False, bad_method_size=False,
                  wrong_method_owner=False, bad_field_start=False,
                  bad_name_index=False):
    values = []
    for item in types:
        values.extend((item["namespace"], item["name"]))
        values.extend(item.get("fields", ()))
        values.extend(item.get("methods", ()))
    values = list(dict.fromkeys(values))
    heap = bytearray()
    indexes = {}
    for value in values:
        indexes[value] = len(heap)
        heap.extend(value.encode("utf-8") + b"\x00")

    fields = []
    methods = []
    type_records = []
    for type_index, item in enumerate(types):
        field_start = len(fields)
        method_start = len(methods)
        for field_name in item.get("fields", ()):
            record = bytearray(12)
            struct.pack_into("<I", record, 0, indexes[field_name])
            fields.append(bytes(record))
        for method_name in item.get("methods", ()):
            record = bytearray(36)
            struct.pack_into("<I", record, 0, indexes[method_name])
            owner = type_index + 1 if wrong_method_owner else type_index
            struct.pack_into("<i", record, 4, owner)
            methods.append(bytes(record))

        record = bytearray(0x58)
        name_index = len(heap) + 5 if bad_name_index else indexes[item["name"]]
        struct.pack_into("<II", record, 0, name_index, indexes[item["namespace"]])
        if bad_field_start:
            field_start = 10000
        struct.pack_into("<ii", record, 0x20, field_start, method_start)
        struct.pack_into(
            "<HHH", record, 0x40,
            len(item.get("methods", ())), 0, len(item.get("fields", ())),
        )
        type_records.append(bytes(record))

    field_blob = b"".join(fields)
    method_blob = b"".join(methods)
    type_blob = b"".join(type_records)
    header_size = 256
    string_offset = header_size
    methods_offset = string_offset + len(heap)
    fields_offset = methods_offset + len(method_blob)
    types_offset = fields_offset + len(field_blob)
    header = bytearray(header_size)
    struct.pack_into("<II", header, 0, magic, version)
    struct.pack_into("<II", header, 24, string_offset, len(heap))
    method_size = len(method_blob) + (1 if bad_method_size else 0)
    type_size = len(type_blob) + (1 if bad_type_size else 0)
    struct.pack_into("<II", header, 0x30, methods_offset, method_size)
    struct.pack_into("<II", header, 0x60, fields_offset, len(field_blob))
    struct.pack_into("<II", header, 0xA0, types_offset, type_size)
    return bytes(header) + bytes(heap) + method_blob + field_blob + type_blob


def write_apk(path, metadata):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(METADATA_MEMBER, metadata)


class Il2CppTypeInventoryTests(unittest.TestCase):
    def test_maps_message_fields_and_serializer_methods_to_owners(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [
                {"namespace": "com.geargames.aow.messages", "name": "LoginRequest",
                 "fields": ["protocolVersion", "token"],
                 "methods": ["get_ProtocolVersion", "set_ProtocolVersion"]},
                {"namespace": "com.geargames.serialization.serializers",
                 "name": "LoginRequestSTSerializer", "methods": ["serialize"]},
                {"namespace": "com.geargames.serialization.serializers",
                 "name": "LoginRequestSTDeserializer", "methods": ["deserialize"]},
                {"namespace": "com.geargames.common.network", "name": "NetworkSettings",
                 "fields": ["HeaderLength", "HeartbeatTimeout"],
                 "methods": ["get_HeartbeatTimeout"]},
            ]
            write_apk(apk, make_metadata(types))
            result = inspect_type_tables(apk)
            by_name = {item["name"]: item for item in result["observed_type_definitions"]}
            self.assertEqual(by_name["LoginRequest"]["field_names"], ["protocolVersion", "token"])
            self.assertEqual(
                by_name["LoginRequestSTSerializer"]["method_names"], ["serialize"]
            )
            self.assertEqual(
                by_name["LoginRequestSTDeserializer"]["method_names"], ["deserialize"]
            )
            self.assertIn("HeaderLength", by_name["NetworkSettings"]["field_names"])
            self.assertTrue(all(item["method_owner_matches"] for item in by_name.values()))

    def test_limits_message_type_registry_fields_to_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "MessageTypes",
                "fields": ["LOGIN_REQUEST", "SESSION_RESTORE_REQUEST", "UNRELATED_SECRET_NAME"],
                "methods": [".ctor"],
            }]
            write_apk(apk, make_metadata(types))
            item = inspect_type_tables(apk)["observed_type_definitions"][0]
            self.assertEqual(item["field_count"], 3)
            self.assertEqual(
                item["field_names"], ["LOGIN_REQUEST", "SESSION_RESTORE_REQUEST"]
            )
            self.assertFalse(item["field_names_complete"])

    def test_rejects_misaligned_type_table(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(
                [{"namespace": "com.geargames.aow.messages", "name": "LoginRequest"}],
                bad_type_size=True,
            ))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_misaligned_method_table(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(
                [{"namespace": "com.geargames.aow.messages", "name": "LoginRequest",
                  "methods": ["serialize"]}],
                bad_method_size=True,
            ))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_method_owner_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(
                [{"namespace": "com.geargames.aow.messages", "name": "LoginRequest",
                  "methods": ["serialize"]}],
                wrong_method_owner=True,
            ))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_field_range_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(
                [{"namespace": "com.geargames.aow.messages", "name": "LoginRequest",
                  "fields": ["token"]}],
                bad_field_start=True,
            ))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_invalid_type_name_index(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(
                [{"namespace": "com.geargames.aow.messages", "name": "LoginRequest"}],
                bad_name_index=True,
            ))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_unsupported_metadata_version(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(
                [{"namespace": "com.geargames.aow.messages", "name": "LoginRequest"}],
                version=30,
            ))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)


if __name__ == "__main__":
    unittest.main()
