# AOW APK forensic analysis — verified initial pass (2026-11-04)

Source: user-provided `aow.apk` in ChatGPT conversation; **not uploaded to this public repository**.

## Integrity and fingerprint

- Size: 256,468,647 bytes (~244.6 MiB)
- SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`
- ZIP entries: **7,368**; `zipfile.testzip()` returned `None` (all entries passed CRC check).
- Unity version string from `assets/bin/Data/globalgamemanagers`: **6000.0.80f1**
- Engine: **Unity 6** with **IL2CPP**, confirmed by `libunity.so`, `libil2cpp.so`, and `assets/bin/Data/Managed/Metadata/global-metadata.dat`.
- ABIs: **arm64-v8a** and **armeabi-v7a**.
- DEX: **6** (`classes.dex` through `classes6.dex`).
- Native `.so` entries: **44**.
- Unity scripting assemblies listed in `ScriptingAssemblies.json`: **223**, including `Assembly-CSharp.dll` (names list, **not** managed source).
- IL2CPP metadata: **26,021,348 bytes**.
- `assets/bin/Data/` entries: **5,684**.
- Unity Addressables bundles: **30**, including **11 map prefab bundles** and **12 minimap bundles**.
- Unity scene files: `level0` through `level6` (**7**).
- Addressables catalog `assets/aa/catalog.json` has **912 internal ID strings**. No literal `http` prefix appears in that catalog's internal IDs; this **does not** prove the app has no remote endpoints.
- Asset metadata catalog versions from `assets/build-metadata.json`: Maps 22, UnitModifications 7, OmniWindowTemplates 17, OmniWindowElements 7.

## What this means

A high-fidelity reconstruction should investigate a compatible Unity 6 project, not default to Godot. Bundled maps, minimaps and visual effects are promising evidence for the asset inventory, but are not automatically editable Unity project sources. The game logic was compiled via IL2CPP; the APK does **not** contain the original Unity C# source project. Server source, protocol and IP have **not** been established.

## Pending deeper analysis

1. Parse binary AndroidManifest.xml using aapt2/apktool (not installed in this initial runtime) for package, SDK levels, permissions and launcher.
2. Inventory all AssetBundles with a Unity asset parser compatible with Unity 6000; record classes and dependencies without publishing copyrighted binary contents.
3. Inspect IL2CPP metadata/type signatures with a compatible analysis tool in an authorized local workspace.
4. Build evidence-based screen/gameplay matrix from authorized observation.
5. Identify endpoint configuration, if any, without exposing secrets or accessing official infrastructure beyond authorized normal use.
6. Determine whether original assets can legally be reused or whether clean-room replacements are needed.

## Reproduce with Python

```python
import hashlib, zipfile
p = "aow.apk"
with open(p, "rb") as f:
    print(hashlib.file_digest(f, "sha256").hexdigest())
with zipfile.ZipFile(p) as z:
    print("entries", len(z.namelist()))
    print("crc_failure", z.testzip())
    print("bundles", sum(x.endswith(".bundle") for x in z.namelist()))
    print("abis", sorted({x.split("/")[1] for x in z.namelist() if x.startswith("lib/")}))
```

No original APK or extracted proprietary content is committed here.
