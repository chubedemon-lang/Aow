"""Synthetic ZIP fixtures only: no proprietary game assets."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("apk_inventory", ROOT / "tools" / "apk_inventory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class InventoryTests(unittest.TestCase):
    def test_synthetic_unity_apk(self):
        with tempfile.TemporaryDirectory() as d:
            apk = pathlib.Path(d) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", bytes.fromhex("03000800") + b"mock")
                z.writestr("classes.dex", b"fake")
                z.writestr("lib/arm64-v8a/libunity.so", b"mock")
                z.writestr("lib/arm64-v8a/libil2cpp.so", b"mock")
                z.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"metadata")
                z.writestr("assets/aa/catalog.json", json.dumps({"m_InternalIds": ["a", "b"], "m_ProviderIds": ["mock"]}))
                z.writestr("assets/aa/Android/example.bundle", b"bundle")
            result = module.analyze(apk)
            self.assertEqual(result["zip_entries"], 7)
            self.assertIsNone(result["zip_crc_first_failure"])
            self.assertTrue(result["unity_il2cpp"])
            self.assertTrue(result["android_manifest_binary_axml"])
            self.assertEqual(result["assetbundles"], 1)
            self.assertEqual(result["addressables_internal_ids"], 2)
            self.assertEqual(result["dex_count"], 1)
            self.assertEqual(result["abis"], ["arm64-v8a"])

    def test_minimal_zip(self):
        with tempfile.TemporaryDirectory() as d:
            apk = pathlib.Path(d) / "minimal.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", b"<manifest/>")
            result = module.analyze(apk)
            self.assertFalse(result["android_manifest_binary_axml"])
            self.assertFalse(result["unity_il2cpp"])
            self.assertEqual(result["assetbundles"], 0)
            self.assertEqual(result["addressables_internal_ids"], 0)
            self.assertIsNone(result["unity_metadata_bytes"])


    def test_noncanonical_dex_and_library_paths_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            apk = pathlib.Path(d) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("AndroidManifest.xml", b"mock")
                for name in ("classes.dex", "classes2.dex", "classes0.dex",
                             "classesfake.dex", "classes3.dex.bak", "nested/classes4.dex"):
                    z.writestr(name, b"fake")
                z.writestr("lib/arm64-v8a/libunity.so", b"mock")
                z.writestr("lib/arm64-v8a/nested/libil2cpp.so", b"mock")
            report = module.analyze(apk)
            self.assertEqual(report["dex_count"], 2)
            self.assertEqual(report["native_library_count"], 1)
            self.assertFalse(report["unity_il2cpp"])

    def test_duplicate_zip_names_rejected(self):
        import warnings
        with tempfile.TemporaryDirectory() as d:
            apk = pathlib.Path(d) / "synthetic.apk"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(apk, "w") as z:
                    z.writestr("AndroidManifest.xml", b"first")
                    z.writestr("AndroidManifest.xml", b"second")
            with self.assertRaisesRegex(ValueError, "duplicate ZIP"):
                module.analyze(apk)

    def test_missing_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            apk = pathlib.Path(d) / "synthetic.apk"
            with zipfile.ZipFile(apk, "w") as z:
                z.writestr("classes.dex", b"fake")
            with self.assertRaisesRegex(ValueError, "missing AndroidManifest"):
                module.analyze(apk)

if __name__ == "__main__":
    unittest.main()
