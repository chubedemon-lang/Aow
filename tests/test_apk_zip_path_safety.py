"""Synthetic APK ZIP path safety tests; no proprietary game bytes."""
import importlib.util
import pathlib
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apk_inventory_path_safety", ROOT / "tools" / "apk_inventory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ZipPathSafetyTests(unittest.TestCase):
    def inspect(self, extra_path):
        with tempfile.TemporaryDirectory() as tmp:
            apk = pathlib.Path(tmp) / "fixture.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"synthetic")
                archive.writestr(extra_path, b"synthetic")
            return module.analyze(apk)

    def test_parent_traversal_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe ZIP entry path"):
            self.inspect("assets/../secret.txt")

    def test_absolute_path_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe ZIP entry path"):
            self.inspect("/absolute/file.txt")

    def test_windows_separator_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe ZIP entry path"):
            self.inspect("assets\\..\\secret.txt")

    def test_dot_component_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsafe ZIP entry path"):
            self.inspect("assets/./file.txt")

    def test_normal_nested_path_accepted(self):
        self.assertEqual(self.inspect("assets/aa/normal.txt")["zip_entries"], 2)


if __name__ == "__main__":
    unittest.main()
