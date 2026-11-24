"""Synthetic-only tests for the read-only IL2CPP metadata inventory."""
import hashlib
import json
import os
import struct
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

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


    def test_path_replacement_after_open_keeps_metadata_and_hash_on_same_inode(self):
        if os.name == "nt":
            self.skipTest("open-file rename semantics differ on Windows")
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "authorized.apk"
            displaced = Path(directory) / "opened-original.apk"
            replacement = Path(directory) / "replacement.apk"
            write_apk(apk, make_metadata(["LoginRequest"]))
            original_bytes = apk.read_bytes()
            write_apk(replacement, make_metadata(["SessionRestoreRequest"]))
            replacement_bytes = replacement.read_bytes()
            real_zipfile = zipfile.ZipFile
            replaced = False

            def replace_path_after_open(file, *args, **kwargs):
                nonlocal replaced
                if not replaced:
                    self.assertTrue(hasattr(file, "fileno"))
                    os.replace(apk, displaced)
                    apk.write_bytes(replacement_bytes)
                    replaced = True
                return real_zipfile(file, *args, **kwargs)

            with mock.patch(
                "tools.il2cpp_metadata_inventory.zipfile.ZipFile",
                side_effect=replace_path_after_open,
            ):
                result = inspect_apk(apk)

            self.assertTrue(replaced)
            self.assertEqual(
                result["apk_sha256"], hashlib.sha256(original_bytes).hexdigest()
            )
            self.assertEqual(result["apk_size_bytes"], len(original_bytes))
            self.assertIn("LoginRequest", result["observed_message_identifier_tokens"])
            self.assertNotIn(
                "SessionRestoreRequest", result["observed_message_identifier_tokens"]
            )

    def test_rejects_in_place_mutation_between_zip_read_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "authorized.apk"
            write_apk(apk, make_metadata(["LoginRequest"]))
            real_zipfile = zipfile.ZipFile

            class MutatingArchive:
                def __init__(self, stream):
                    self.archive = real_zipfile(stream)

                def __enter__(self):
                    self.archive.__enter__()
                    return self

                def __exit__(self, *args):
                    result = self.archive.__exit__(*args)
                    with apk.open("ab") as changed:
                        changed.write(b"mutation")
                    return result

                def infolist(self):
                    return self.archive.infolist()

                def open(self, *args, **kwargs):
                    return self.archive.open(*args, **kwargs)

            with mock.patch(
                "tools.il2cpp_metadata_inventory.zipfile.ZipFile",
                side_effect=lambda stream, *args, **kwargs: MutatingArchive(stream),
            ):
                with self.assertRaisesRegex(
                    MetadataInventoryError, "changed while reading"
                ):
                    inspect_apk(apk)

    def test_rejects_fifo_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO creation is unavailable on this platform")
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "input.apk"
            os.mkfifo(fifo)
            with self.assertRaises(MetadataInventoryError):
                inspect_apk(fifo)


if __name__ == "__main__":
    unittest.main()
