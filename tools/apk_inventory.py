#!/usr/bin/env python3
"""Read-only APK structural inventory; stdlib only. Does not extract game assets."""
import argparse, hashlib, json, pathlib, re, zipfile

MAX_CATALOG_BYTES = 8 * 1024 * 1024

DEX_NAME = re.compile(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z')

def analyze(path):
    p = pathlib.Path(path)
    with p.open("rb") as f:
        sha256 = hashlib.file_digest(f, "sha256").hexdigest()
    with zipfile.ZipFile(p) as z:
        entries = z.infolist()
        if len(entries) > 100000:
            raise ValueError('too many ZIP entries')
        if any(item.flag_bits & 1 for item in entries):
            raise ValueError('encrypted ZIP entries are not supported')
        names = [item.filename for item in entries]
        if len(names) != len(set(names)):
            raise ValueError('duplicate ZIP entries')
        if 'AndroidManifest.xml' not in names:
            raise ValueError('missing AndroidManifest.xml')
        bundles = sorted(n for n in names if n.endswith(".bundle"))
        abis = sorted({n.split("/")[1] for n in names if n.startswith("lib/") and len(n.split("/")) == 3 and n.endswith(".so")})
        dex = sorted(n for n in names if DEX_NAME.fullmatch(n))
        with z.open("AndroidManifest.xml") as manifest_stream:
            manifest_magic = manifest_stream.read(4)
        catalog = {}
        if "assets/aa/catalog.json" in names:
            if z.getinfo("assets/aa/catalog.json").file_size > MAX_CATALOG_BYTES:
                raise ValueError("Addressables catalog exceeds size limit")
            try:
                catalog = json.loads(z.read("assets/aa/catalog.json"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("invalid Addressables catalog JSON") from exc
            if not isinstance(catalog, dict):
                raise ValueError("Addressables catalog must be a JSON object")
            if not isinstance(catalog.get("m_InternalIds", []), list) or not isinstance(catalog.get("m_ProviderIds", []), list):
                raise ValueError("Addressables catalog fields must be lists")
            if any(not isinstance(value, str) for field in ("m_InternalIds", "m_ProviderIds") for value in catalog.get(field, [])):
                raise ValueError("Addressables catalog ID entries must be strings")
        maps = [n for n in bundles if "/built-inmaps_" in n]
        minimaps = [n for n in bundles if "/built-inminimaps_" in n]
        native = sorted(n for n in names if n.startswith("lib/") and len(n.split("/")) == 3 and n.split("/")[1] and n.split("/")[2].endswith(".so"))
        return {
            "file_size_bytes": p.stat().st_size, "sha256": sha256,
            "zip_entries": len(names), "zip_crc_first_failure": z.testzip(),
            "android_manifest_binary_axml": manifest_magic == bytes.fromhex("03000800"),
            "abis": abis, "dex_count": len(dex), "native_library_count": len(native),
            "unity_il2cpp": all(any(n.endswith("/"+lib) for n in native) for lib in ("libunity.so","libil2cpp.so")) and "assets/bin/Data/Managed/Metadata/global-metadata.dat" in names,
            "unity_metadata_bytes": z.getinfo("assets/bin/Data/Managed/Metadata/global-metadata.dat").file_size if "assets/bin/Data/Managed/Metadata/global-metadata.dat" in names else None,
            "assetbundles": len(bundles), "map_bundles": maps, "minimap_bundles": minimaps,
            "addressables_internal_ids": len(catalog.get("m_InternalIds", [])),
            "addressables_provider_ids": catalog.get("m_ProviderIds", []),
            "largest_files": [{"path":i.filename,"bytes":i.file_size} for i in sorted(z.infolist(), key=lambda i:i.file_size, reverse=True)[:12]],
        }

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("apk", help="Path to authorized APK")
    ap.add_argument("--output", help="Optional JSON report path")
    args = ap.parse_args()
    report = json.dumps(analyze(args.apk), indent=2, ensure_ascii=False)
    if args.output:
        pathlib.Path(args.output).write_text(report+"\n", encoding="utf-8")
    else:
        print(report)
