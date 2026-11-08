"""Synthetic ZIP boundary tests; never inspect or publish real APK bytes."""
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from server.offline_apk_inventory import ApkInventoryError, inventory_apk


class InventorySafetyBoundsTests(unittest.TestCase):
    def test_apk_byte_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("safe.txt", "abc")
            with patch("server.offline_apk_inventory.MAX_APK_BYTES", path.stat().st_size - 1):
                with self.assertRaisesRegex(ApkInventoryError, "APK size"):
                    inventory_apk(path)

    def test_member_count_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("one.txt", "1")
                archive.writestr("two.txt", "2")
            with patch("server.offline_apk_inventory.MAX_MEMBERS", 1):
                with self.assertRaisesRegex(ApkInventoryError, "too many"):
                    inventory_apk(path)

    def test_total_uncompressed_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("one.txt", "abc")
                archive.writestr("two.txt", "def")
            with patch("server.offline_apk_inventory.MAX_UNCOMPRESSED_BYTES", 5):
                with self.assertRaisesRegex(ApkInventoryError, "uncompressed size"):
                    inventory_apk(path)

    def test_directory_entries_are_not_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("assets/", "")
                archive.writestr("assets/one.dat", "x")
            result = inventory_apk(path)
            self.assertEqual(result.member_count, 1)
            self.assertEqual(result.uncompressed_bytes, 1)

    def test_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.apk"
            with zipfile.ZipFile(original, "w") as archive:
                archive.writestr("one.dat", "x")
            link = root / "link.apk"
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("symlink unavailable on this platform")
            with self.assertRaisesRegex(ApkInventoryError, "regular local file"):
                inventory_apk(link)


if __name__ == "__main__":
    unittest.main()
