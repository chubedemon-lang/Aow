"""Synthetic ZIP symlink metadata regression tests. No real APK input."""
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from server.offline_apk_inventory import ApkInventoryError, inventory_apk


class ZipMemberTypeTests(unittest.TestCase):
    def test_unix_symlink_member_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            link = zipfile.ZipInfo("assets/link.dat")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(link, "target.dat")
            with self.assertRaisesRegex(ApkInventoryError, "symlink archive member"):
                inventory_apk(path)

    def test_unix_regular_member_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.apk"
            regular = zipfile.ZipInfo("assets/regular.dat")
            regular.create_system = 3
            regular.external_attr = (stat.S_IFREG | 0o644) << 16
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(regular, b"safe")
            result = inventory_apk(path)
            self.assertEqual(result.member_count, 1)
            self.assertEqual(result.uncompressed_bytes, 4)


if __name__ == "__main__":
    unittest.main()
