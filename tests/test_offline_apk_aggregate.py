"""Synthetic-only tests for bounded, non-extracting APK inventory."""
import tempfile
import unittest
import zipfile
from pathlib import Path
from server.offline_apk_inventory import ApkInventoryError, inventory_apk

class AggregateInventoryTests(unittest.TestCase):
    def test_aggregate_no_filenames(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.apk"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("assets/private_config.json", "{}")
                archive.writestr("lib/example.so", "binary")
                archive.writestr("nested/SECRET", "test")
            result = inventory_apk(path)
            self.assertEqual(result.member_count, 3)
            self.assertEqual(result.uncompressed_bytes, 12)
            self.assertEqual(dict(result.extension_counts), {".json": 1, ".so": 1, "<other>": 1})
            self.assertEqual(len(result.sha256), 64)
            self.assertNotIn("private_config", repr(result))

    def test_invalid_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.apk"
            path.write_bytes(b"not a zip")
            with self.assertRaises(ApkInventoryError):
                inventory_apk(path)

    def test_missing_path(self):
        with self.assertRaises(ApkInventoryError):
            inventory_apk("/nonexistent/authorized-local.apk")

    def test_empty_zip_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.apk"
            with zipfile.ZipFile(path, "w"):
                pass
            self.assertEqual(inventory_apk(path).member_count, 0)

if __name__ == "__main__":
    unittest.main()
