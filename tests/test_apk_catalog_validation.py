"""Synthetic-only regression tests for bounded Addressables catalog inspection."""
import importlib.util
import pathlib
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apk_inventory_catalog", ROOT / "tools" / "apk_inventory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CatalogValidationTests(unittest.TestCase):
    def inspect_catalog(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            apk = pathlib.Path(tmp) / "fixture.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("AndroidManifest.xml", b"synthetic")
                archive.writestr("assets/aa/catalog.json", data)
            return module.analyze(apk)

    def test_invalid_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid Addressables catalog"):
            self.inspect_catalog(b"{bad json")

    def test_non_object_catalog_rejected(self):
        with self.assertRaisesRegex(ValueError, "JSON object"):
            self.inspect_catalog(b"[]")

    def test_wrong_field_types_rejected(self):
        with self.assertRaisesRegex(ValueError, "fields must be lists"):
            self.inspect_catalog(b'{"m_InternalIds": "not-a-list"}')

    def test_oversized_catalog_rejected_before_read(self):
        with self.assertRaisesRegex(ValueError, "exceeds size limit"):
            self.inspect_catalog(b" " * (module.MAX_CATALOG_BYTES + 1))

    def test_valid_catalog(self):
        result = self.inspect_catalog(b'{"m_InternalIds":["a"],"m_ProviderIds":["provider"]}')
        self.assertEqual(result["addressables_internal_ids"], 1)
        self.assertEqual(result["addressables_provider_ids"], ["provider"])


if __name__ == "__main__":
    unittest.main()
