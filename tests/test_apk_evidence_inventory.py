"""Tests for offline metadata-only APK inventory (synthetic ZIPs only)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "apk_evidence_inventory.py"
spec = importlib.util.spec_from_file_location("apk_evidence_inventory", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ApkEvidenceInventoryTests(unittest.TestCase):
    def test_counts_and_no_endpoint_leak(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = Path(folder) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"not-real-dex")
                archive.writestr("lib/arm64-v8a/libnet.so", b"dummy")
                archive.writestr("assets/secret-token.txt", b"SECRET_PRIVATE_VALUE")
                archive.writestr("res/raw/config.xml", b"https://private.example/test")
            result = module.inventory(apk)
            self.assertEqual(result["zip_entry_counts"], {
                "dex": 1, "native_libraries": 1, "assets": 1, "other": 1
            })
            self.assertFalse(result["protocol_verified"])
            self.assertNotIn("SECRET_PRIVATE_VALUE", str(result))
            self.assertNotIn("private.example", str(result))
            self.assertNotIn("secret-token.txt", str(result))
            self.assertEqual(len(result["sha256"]), 64)

    def test_missing_file(self):
        with self.assertRaises(ValueError):
            module.inventory(Path("/definitely-not-an-existing-apk-file.apk"))

    def test_invalid_archive(self):
        with tempfile.TemporaryDirectory() as folder:
            apk = Path(folder) / "bad.apk"
            apk.write_bytes(b"not a zip")
            with self.assertRaises(zipfile.BadZipFile):
                module.inventory(apk)

if __name__ == "__main__":
    unittest.main()
