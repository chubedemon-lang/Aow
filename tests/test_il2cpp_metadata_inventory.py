"""Synthetic-only tests for the read-only IL2CPP metadata inventory."""
import json
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from tools.il2cpp_metadata_inventory import (
    METADATA_MAGIC,
    METADATA_MEMBER,
    MetadataInventoryError,
    inspect_apk,
)


def make_metadata(strings, *, version=31, magic=METADATA_MAGIC,
                  string_offset=32, declared_size=None):
    heap = b"\x00".join(value.encode("ascii") for value in strings) + b"\x00"
    header = bytearray(32)
    struct.pack_into("<II", header, 0, magic, version)
    struct.pack_into("<II", header, 24, string_offset,
                     len(heap) if declared_size is None else declared_size)
    if string_offset < 32:
        return bytes(header) + heap
    return bytes(header) + (b"\x00" * (string_offset - 32)) + heap


def write_apk(path, metadata=None, *, duplicate=False):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if metadata is not None:
            archive.writestr(METADATA_MEMBER, metadata)
            if duplicate:
                archive.writestr(METADATA_MEMBER, metadata)


class Il2CppMetadataInventoryTests(unittest.TestCase):
    def test_reads_only_allowlisted_protocol_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            metadata = make_metadata([
                "com.geargames.aow.messages",
                "com.geargames.common.network",
                "NetworkSocket",
                "MessageMeta",
                "LoginRequest",
                "LoginRequestSTSerializer",
                "LoginRequestSTDeserializer",
                "SessionRestoreRequest",
                "SessionRestoreRequestSTSerializer",
                "SessionRestoreRequestSTDeserializer",
                "https://private.example/path?token=do-not-emit",
                "arbitrary-secret-value",
            ])
            write_apk(apk, metadata)
            result = inspect_apk(apk)
            self.assertEqual(result["metadata_version"], 31)
            self.assertIn("LoginRequest", result["observed_message_identifier_tokens"])
            self.assertIn(
                "LoginRequest",
                result["message_identifiers_with_serializer_and_deserializer_tokens"],
            )
            self.assertIn(
                "SessionRestoreRequest",
                result["message_identifiers_with_serializer_and_deserializer_tokens"],
            )
            serialized = json.dumps(result)
            self.assertNotIn("private.example", serialized)
            self.assertNotIn("do-not-emit", serialized)
            self.assertNotIn("arbitrary-secret-value", serialized)

    def test_unpaired_serializer_is_not_reported_as_a_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(["LoginRequest", "LoginRequestSTSerializer"]))
            result = inspect_apk(apk)
            self.assertIn("LoginRequest", result["observed_message_identifier_tokens"])
            self.assertNotIn(
                "LoginRequest",
                result["message_identifiers_with_serializer_and_deserializer_tokens"],
            )

    def test_rejects_missing_metadata_member(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, None)
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(apk)

    def test_rejects_duplicate_metadata_members(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                write_apk(apk, make_metadata(["LoginRequest"]), duplicate=True)
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(apk)

    def test_rejects_bad_magic(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(["LoginRequest"], magic=0x12345678))
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(apk)

    def test_rejects_unsupported_metadata_version(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(["LoginRequest"], version=30))
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(apk)

    def test_rejects_out_of_bounds_string_heap(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "synthetic.apk"
            write_apk(apk, make_metadata(["LoginRequest"], declared_size=4096))
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(apk)

    def test_rejects_invalid_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "invalid.apk"
            apk.write_bytes(b"not a zip")
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(apk)

    def test_rejects_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.apk"
            link = Path(directory) / "link.apk"
            write_apk(target, make_metadata(["LoginRequest"]))
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform")
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(link)


if __name__ == "__main__":
    unittest.main()
