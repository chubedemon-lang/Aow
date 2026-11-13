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
                  bad_name_index=False, bad_parameter_size=False,
                  bad_parameter_range=False, bad_field_default_size=False,
                  bad_default_data_index=False):
    values = []
    for item in types:
        values.extend((item["namespace"], item["name"]))
        values.extend(item.get("fields", ()))
        values.extend(item.get("methods", ()))
        for method_name in item.get("methods", ()):
            signature = item.get("method_signatures", {}).get(method_name, {})
            values.extend(
                parameter["name"] for parameter in signature.get("parameters", ())
            )
    values = list(dict.fromkeys(values))
    heap = bytearray()
    indexes = {}
    for value in values:
        indexes[value] = len(heap)
        heap.extend(value.encode("utf-8") + b"\x00")

    fields = []
    methods = []
    parameters = []
    type_records = []
    field_defaults = []
    for type_index, item in enumerate(types):
        field_start = len(fields)
        method_start = len(methods)
        for field_name in item.get("fields", ()):
            field_index = len(fields)
            record = bytearray(12)
            struct.pack_into(
                "<IiI", record, 0,
                indexes[field_name],
                item.get("field_type_indexes", {}).get(field_name, 0),
                item.get("field_tokens", {}).get(field_name, 0),
            )
            fields.append(bytes(record))
            default = item.get("field_defaults", {}).get(field_name)
            if default is not None:
                data_index = 1000 if bad_default_data_index else default.get("data_index", 0)
                field_defaults.append((
                    field_index,
                    default.get("type_index", 0),
                    data_index,
                ))
        for method_name in item.get("methods", ()):
            signature = item.get("method_signatures", {}).get(method_name, {})
            parameter_start = len(parameters)
            method_parameters = signature.get("parameters", ())
            for parameter in method_parameters:
                record = bytearray(12)
                struct.pack_into(
                    "<IIi", record, 0,
                    indexes[parameter["name"]],
                    parameter.get("token", 0),
                    parameter.get("type_index", 0),
                )
                parameters.append(bytes(record))
            if bad_parameter_range and method_parameters:
                parameter_start = 10000
            record = bytearray(36)
            owner = type_index + 1 if wrong_method_owner else type_index
            struct.pack_into(
                "<IiiIiiIHHHH", record, 0,
                indexes[method_name],
                owner,
                signature.get("return_type_index", 0),
                signature.get("return_parameter_token", 0),
                parameter_start,
                signature.get("generic_container_index", -1),
                signature.get("token", 0),
                signature.get("flags", 0),
                signature.get("iflags", 0),
                signature.get("slot", 0),
                len(method_parameters),
            )
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
    parameter_blob = b"".join(parameters)
    type_blob = b"".join(type_records)
    field_default_blob = b"".join(
        struct.pack("<iii", *item) for item in field_defaults
    )
    default_data_blob = bytes(range(16))
    header_size = 256
    string_offset = header_size
    methods_offset = string_offset + len(heap)
    parameters_offset = methods_offset + len(method_blob)
    fields_offset = parameters_offset + len(parameter_blob)
    types_offset = fields_offset + len(field_blob)
    field_defaults_offset = types_offset + len(type_blob)
    default_data_offset = field_defaults_offset + len(field_default_blob)
    header = bytearray(header_size)
    struct.pack_into("<II", header, 0, magic, version)
    struct.pack_into("<II", header, 24, string_offset, len(heap))
    struct.pack_into("<II", header, 0x30, methods_offset,
                     len(method_blob) + (1 if bad_method_size else 0))
    struct.pack_into("<II", header, 0x40, field_defaults_offset,
                     len(field_default_blob) + (1 if bad_field_default_size else 0))
    struct.pack_into("<II", header, 0x48, default_data_offset, len(default_data_blob))
    struct.pack_into("<II", header, 0x58, parameters_offset,
                     len(parameter_blob) + (1 if bad_parameter_size else 0))
    struct.pack_into("<II", header, 0x60, fields_offset, len(field_blob))
    struct.pack_into("<II", header, 0xA0, types_offset,
                     len(type_blob) + (1 if bad_type_size else 0))
    return (bytes(header) + bytes(heap) + method_blob + parameter_blob
            + field_blob + type_blob + field_default_blob + default_data_blob)


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
                 "field_type_indexes": {"protocolVersion": 17, "token": 42},
                 "field_tokens": {"protocolVersion": 0x04000001, "token": 0x04000002},
                 "field_defaults": {"protocolVersion": {"type_index": 9, "data_index": 3}},
                 "methods": ["get_ProtocolVersion", "set_ProtocolVersion"],
                 "method_signatures": {
                     "get_ProtocolVersion": {"return_type_index": 17, "token": 0x06000001},
                     "set_ProtocolVersion": {
                         "return_type_index": 0, "token": 0x06000002,
                         "parameters": [{"name": "value", "type_index": 17, "token": 0x08000001}],
                     },
                 }},
                {"namespace": "com.geargames.serialization.serializers",
                 "name": "LoginRequestSTSerializer", "methods": ["serialize"]},
                {"namespace": "com.geargames.serialization.serializers",
                 "name": "LoginRequestSTDeserializer", "methods": ["deserialize"]},
                {"namespace": "com.geargames.common.network", "name": "NetworkSettings",
                 "fields": ["HeaderLength", "HeartbeatTimeout"],
                 "field_defaults": {"HeaderLength": {"type_index": 9, "data_index": 2}},
                 "methods": ["get_HeartbeatTimeout"]},
            ]
            write_apk(apk, make_metadata(types))
            result = inspect_type_tables(apk)
            by_name = {item["name"]: item for item in result["observed_type_definitions"]}
            self.assertEqual(by_name["LoginRequest"]["field_names"], ["protocolVersion", "token"])
            fields_by_name = {
                item["name"]: item for item in by_name["LoginRequest"]["field_records"]
            }
            self.assertEqual(fields_by_name["protocolVersion"]["type_index"], 17)
            self.assertEqual(fields_by_name["token"]["type_index"], 42)
            self.assertEqual(fields_by_name["protocolVersion"]["metadata_token"], 0x04000001)
            self.assertTrue(fields_by_name["protocolVersion"]["default_value_record_present"])
            self.assertEqual(fields_by_name["protocolVersion"]["default_value_type_index"], 9)
            self.assertEqual(fields_by_name["protocolVersion"]["default_value_data_index"], 3)
            self.assertFalse(fields_by_name["token"]["default_value_record_present"])
            self.assertIsNone(fields_by_name["token"]["default_value_type_index"])
            methods_by_name = {
                item["name"]: item for item in by_name["LoginRequest"]["method_records"]
            }
            self.assertEqual(methods_by_name["get_ProtocolVersion"]["return_type_index"], 17)
            self.assertEqual(methods_by_name["set_ProtocolVersion"]["parameters"], [{
                "name": "value", "type_index": 17, "metadata_token": 0x08000001,
            }])
            self.assertEqual(
                by_name["LoginRequestSTSerializer"]["method_names"], ["serialize"]
            )
            self.assertEqual(
                by_name["LoginRequestSTDeserializer"]["method_names"], ["deserialize"]
            )
            self.assertIn("HeaderLength", by_name["NetworkSettings"]["field_names"])
            network_fields = {
                item["name"]: item for item in by_name["NetworkSettings"]["field_records"]
            }
            self.assertTrue(network_fields["HeaderLength"]["default_value_record_present"])
            self.assertFalse(network_fields["HeartbeatTimeout"]["default_value_record_present"])
            self.assertTrue(all(item["method_owner_matches"] for item in by_name.values()))

    def test_maps_dispatcher_listener_delegate_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [
                {
                    "namespace": "com.geargames.common.network",
                    "name": "MessageDispatcher",
                    "fields": [
                        "m_listeners", "m_listenersByType",
                        "m_lastProcessedServerSequenceNumber",
                    ],
                    "field_type_indexes": {
                        "m_listeners": 10,
                        "m_listenersByType": 11,
                        "m_lastProcessedServerSequenceNumber": 12,
                    },
                    "methods": ["TypeRegister", "SafeRegister"],
                    "method_signatures": {
                        "TypeRegister": {
                            "parameters": [
                                {"name": "type", "type_index": 20},
                                {"name": "listener", "type_index": 21},
                            ],
                        },
                        "SafeRegister": {
                            "parameters": [
                                {"name": "type", "type_index": 20},
                                {"name": "listener", "type_index": 21},
                            ],
                        },
                    },
                },
                {
                    "namespace": "com.geargames.common.network",
                    "name": "OnMessageReceivedDelegate",
                    "methods": [".ctor", "Invoke"],
                    "method_signatures": {
                        ".ctor": {
                            "parameters": [
                                {"name": "object", "type_index": 30},
                                {"name": "method", "type_index": 31},
                            ],
                        },
                        "Invoke": {
                            "parameters": [
                                {"name": "message", "type_index": 32},
                            ],
                        },
                    },
                },
                {
                    "namespace": "",
                    "name": "OnMessageReceivedDelegateData",
                    "fields": ["Delegate"],
                    "field_type_indexes": {"Delegate": 33},
                },
            ]
            write_apk(apk, make_metadata(types))
            result = inspect_type_tables(apk)
            by_key = {
                (item["namespace"], item["name"]): item
                for item in result["observed_type_definitions"]
            }

            dispatcher = by_key[("com.geargames.common.network", "MessageDispatcher")]
            self.assertEqual(
                dispatcher["field_names"],
                [
                    "m_listeners", "m_listenersByType",
                    "m_lastProcessedServerSequenceNumber",
                ],
            )
            methods = {item["name"]: item for item in dispatcher["method_records"]}
            self.assertEqual(
                methods["SafeRegister"]["parameters"],
                [
                    {"name": "type", "type_index": 20, "metadata_token": 0},
                    {"name": "listener", "type_index": 21, "metadata_token": 0},
                ],
            )
            self.assertEqual(
                methods["TypeRegister"]["parameters"],
                methods["SafeRegister"]["parameters"],
            )

            delegate = by_key[
                ("com.geargames.common.network", "OnMessageReceivedDelegate")
            ]
            delegate_methods = {
                item["name"]: item for item in delegate["method_records"]
            }
            self.assertEqual(
                delegate_methods[".ctor"]["parameters"],
                [
                    {"name": "object", "type_index": 30, "metadata_token": 0},
                    {"name": "method", "type_index": 31, "metadata_token": 0},
                ],
            )
            self.assertEqual(
                delegate_methods["Invoke"]["parameters"],
                [{"name": "message", "type_index": 32, "metadata_token": 0}],
            )

            delegate_data = by_key[("", "OnMessageReceivedDelegateData")]
            self.assertEqual(delegate_data["field_names"], ["Delegate"])
            self.assertEqual(
                delegate_data["field_records"][0]["type_index"], 33
            )
            self.assertTrue(all(item["method_owner_matches"] for item in by_key.values()))

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

    def test_rejects_field_default_data_index_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "fields": ["protocolVersion"],
                "field_defaults": {"protocolVersion": {"type_index": 9, "data_index": 2}},
            }]
            write_apk(apk, make_metadata(types, bad_default_data_index=True))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_misaligned_field_default_table(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "fields": ["protocolVersion"],
                "field_defaults": {"protocolVersion": {"type_index": 9, "data_index": 2}},
            }]
            write_apk(apk, make_metadata(types, bad_field_default_size=True))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_method_parameter_range_out_of_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "methods": ["set_Token"],
                "method_signatures": {
                    "set_Token": {
                        "parameters": [{"name": "value", "type_index": 3}],
                    },
                },
            }]
            write_apk(apk, make_metadata(types, bad_parameter_range=True))
            with self.assertRaises(MetadataInventoryError):
                inspect_type_tables(apk)

    def test_rejects_misaligned_parameter_table(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "methods": ["set_Token"],
                "method_signatures": {
                    "set_Token": {
                        "parameters": [{"name": "value", "type_index": 3}],
                    },
                },
            }]
            write_apk(apk, make_metadata(types, bad_parameter_size=True))
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

    def test_rejects_negative_target_field_type_index(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "fields": ["token"],
                "field_type_indexes": {"token": -1},
            }]
            write_apk(apk, make_metadata(types))
            with self.assertRaisesRegex(MetadataInventoryError, "field type index is negative"):
                inspect_type_tables(apk)

    def test_rejects_negative_field_default_type_index(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "fields": ["token"],
                "field_defaults": {"token": {"type_index": -1, "data_index": 0}},
            }]
            write_apk(apk, make_metadata(types))
            with self.assertRaisesRegex(MetadataInventoryError, "field default type index is negative"):
                inspect_type_tables(apk)

    def test_rejects_negative_target_method_return_type_index(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "methods": ["get_Token"],
                "method_signatures": {"get_Token": {"return_type_index": -1}},
            }]
            write_apk(apk, make_metadata(types))
            with self.assertRaisesRegex(MetadataInventoryError, "method return type index is negative"):
                inspect_type_tables(apk)

    def test_rejects_negative_target_method_parameter_type_index(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            types = [{
                "namespace": "com.geargames.aow.messages",
                "name": "LoginRequest",
                "methods": ["set_Token"],
                "method_signatures": {
                    "set_Token": {
                        "parameters": [{"name": "value", "type_index": -1}],
                    },
                },
            }]
            write_apk(apk, make_metadata(types))
            with self.assertRaisesRegex(MetadataInventoryError, "method parameter type index is negative"):
                inspect_type_tables(apk)


if __name__ == "__main__":
    unittest.main()
