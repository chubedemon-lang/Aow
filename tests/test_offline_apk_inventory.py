"""Regression tests for safe APK ZIP inventory with synthetic fixtures only."""
import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.offline_apk_inventory import inspect_apk


class OfflineInventoryTests(unittest.TestCase):
    def test_synthetic_il2cpp_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", b"fake")
                archive.writestr("classes2.dex", b"fake")
                archive.writestr("lib/arm64-v8a/libunity.so", b"fake")
                archive.writestr("lib/arm64-v8a/libil2cpp.so", b"fake")
                archive.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
                    (0xFAB11BAF).to_bytes(4, "little") + (31).to_bytes(4, "little"))
            result = inspect_apk(path)
            self.assertEqual(result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(result["dex_count"], 2)
            self.assertEqual(result["native_abis"], ["arm64-v8a"])
            self.assertTrue(result["unity_library_present"])
            self.assertTrue(result["il2cpp_library_present"])
            self.assertEqual(result["il2cpp_metadata"]["version"], 31)

    def test_invalid_metadata_magic_does_not_claim_version(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"12345678")
            result = inspect_apk(path)
            self.assertFalse(result["il2cpp_metadata"]["valid_magic"])
            self.assertIsNone(result["il2cpp_metadata"]["version"])


    def test_only_valid_multidex_names_count(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(path, "w") as archive:
                for name in ("classes.dex", "classes2.dex", "classes0.dex",
                             "classesfake.dex", "classes3.dex.bak", "classes-1.dex"):
                    archive.writestr(name, b"fake")
            self.assertEqual(inspect_apk(path)["dex_count"], 2)

    def test_invalid_zip_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.apk"
            path.write_bytes(b"not a ZIP")
            with self.assertRaises(zipfile.BadZipFile):
                inspect_apk(path)


if __name__ == "__main__":
    unittest.main()
