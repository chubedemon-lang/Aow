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

1. Trace the effective runtime use of `NetworkSettings.HeaderLength`; do not equate the four-byte receive-side immediate with that field until the relationship is established.
2. Recover LoginRequest field order from native field loads and serializer/deserializer data flow; metadata declaration order and helper-call counts alone are insufficient.
3. Verify how MessageTypes metadata values are mapped to message classes and whether those values are used on the active wire path.
4. Establish compression/encryption activation and the complete sender/receiver byte relationship using an authorized, redacted client-side fixture or local runtime trace.
5. Inventory AssetBundles with a Unity 6000-compatible parser, recording only safe metadata and dependencies without publishing copyrighted binary contents.
6. Build an evidence-based screen/gameplay matrix from authorized observation and determine whether clean-room replacement assets are required.

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

## Follow-up inspection — 2026-11-04

Inspected the uploaded APK directly using Python `zipfile` and `json`, without modifying or extracting its game assets. Reproducible inventory script committed as `tools/apk_inventory.py`.

- `AndroidManifest.xml` begins with `03000800` (Android binary XML). Package name, launcher, SDK and permissions require a binary-AXML parser; not guessed.
- The largest entry is `lib/arm64-v8a/libil2cpp.so` (166,150,720 bytes uncompressed); ARMv7 IL2CPP is 138,042,764 bytes.
- Addressables providers include `GearGames.AOW.AddressablesExtensions.UniversalBundleProvider` and `UnityEngine.ResourceManagement.ResourceProviders.BundledAssetProvider`. This is evidence of an AOW-specific bundle provider, not evidence of a particular remote server.
- Map bundle identifiers: `1_2`, `1_3`, `1_3_new`, `1_4`, `1_5`, `1_5_new`, `1_6`, `3_2`, `4_1`, `pvp_11`, `pvp_35`.
- There are matching minimap bundles for those 11 map identifiers, plus `minimap_empty`.
- Other named bundle groups include `built-inomniwindow`, `built-invfx`, `decorations-common`, `decorations-desert`, `decorations-jungle`, `defaultlocalgroup`.
- `assets/aa/catalog.json` contains 912 internal IDs. No actual endpoint or IP has yet been verified.

Run: `python tools/apk_inventory.py /path/to/aow.apk --output apk_inventory.json`. Keep output local until reviewed for sensitive configuration. Do not commit APK or extracted proprietary resources.


## Follow-up inspection — 2026-11-12 (read-only re-verification)

The previously supplied APK was re-materialized into a private workspace and read successfully. It was not modified, and neither the APK nor extracted game assets/native libraries were uploaded to GitHub.

- APK size: **256,468,647 bytes**; SHA-256 re-computed and matched the existing fingerprint above.
- ZIP entries: **7,368**; a full CRC test passed.
- Binary Android manifest: package `com.geargames.aow`, version name `6.11.2`, version code `39430`, minimum SDK **24**, target SDK **36**.
- Launcher activity: `com.trophit.MyUnityPlayerActivity`.
- The manifest sets `usesCleartextTraffic=true`; this is only an Android platform policy flag and does **not** prove that gameplay traffic is plain HTTP or identify the active transport.
- `global-metadata.dat`: **26,021,348 bytes**, magic `0xfab11baf`, version **31**.
- `lib/arm64-v8a/libil2cpp.so`: **166,150,720 bytes**, ELF64 little-endian AArch64 shared object.

A fresh private read-only metadata/ELF pass independently reproduced the existing aggregate codegen mapping: **165/165** metadata images matched native modules; **197,631** method definitions mapped to **197,631** pointer slots; **164,023** slots had relative relocations to executable targets. The exact APK SHA-256 remained unchanged.

The bounded native `Receiver.Cycle` window was rechecked at instruction/data-flow level: the initial stream-buffer setup supplies count **4** to the first read/copy, then calls `SimpleDeserializer.deserializeInt`. In the non-HTTP-marker branch, the returned integer is reused as the next buffer read count. The same bounded window contains a later integer read, decompression, message-metadata construction and queue handoff. The primitive helper bodies independently show high-byte/high-word-first composition for 16- and 32-bit integer operations.

The bounded `Sender.Cycle` window contains two `serializeInt` callsites, a `ZipCompression` callsite, a buffer-length setup and two stream-buffer writes. The window is not a control-flow graph, so the two integer writes are not assigned field semantics here.

The LoginRequest serializer window has direct helper callsites for 19 integers, 16 strings, 2 longs and 1 boolean; its deserializer window has 14 integers, 16 strings, 2 longs and 1 boolean. These are bounded-window direct-call counts, not a recovered field order. The differing integer counts remain unresolved.

**Conclusion:** the four-byte big-endian length-prefix candidate is stronger and reproducible as static native evidence, with a receive-side integer-driven second read. It is still not a verified complete wire frame: the runtime relationship to `NetworkSettings.HeaderLength`, active branch behavior, compression/encryption placement, message IDs, handshake and LoginRequest field order remain unverified. No packet capture was available and no official endpoint/server was contacted.
