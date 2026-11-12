"""Regression tests for safe APK ZIP inventory with synthetic fixtures only."""
import hashlib
import stat
import warnings
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


    def test_apk_byte_limit_is_checked_before_hashing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.dat", b"x")
            with patch("tools.offline_apk_inventory.MAX_APK_BYTES", path.stat().st_size - 1):
                with self.assertRaisesRegex(ValueError, "APK size"):
                    inspect_apk(path)

    def test_total_uncompressed_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("one.dat", b"abc")
                archive.writestr("two.dat", b"def")
            with patch("tools.offline_apk_inventory.MAX_UNCOMPRESSED_BYTES", 5):
                with self.assertRaisesRegex(ValueError, "uncompressed size"):
                    inspect_apk(path)

    def test_duplicate_member_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr("classes.dex", b"first")
                    archive.writestr("classes.dex", b"second")
            with self.assertRaisesRegex(ValueError, "duplicate ZIP member"):
                inspect_apk(path)

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            link = zipfile.ZipInfo("lib/arm64-v8a/libfake.so")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(link, b"target")
            with self.assertRaisesRegex(ValueError, "symlink ZIP member"):
                inspect_apk(path)

    def test_non_regular_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "regular local file"):
                inspect_apk(directory)

    def test_symlink_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.apk"
            with zipfile.ZipFile(original, "w") as archive:
                archive.writestr("one.dat", b"x")
            link = root / "link.apk"
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable on this platform")
            with self.assertRaisesRegex(ValueError, "regular local file"):
                inspect_apk(link)


if __name__ == "__main__":
    unittest.main()
