# Authorized offline APK inventory

Run `python tools/offline_apk_inventory.py /private/path/aow.apk` on a machine that holds the authorized APK. The script uses only the Python standard library; it reads ZIP directory metadata, a bounded 8-byte IL2CPP header, and a streaming SHA-256. It does not extract, execute, contact endpoints, or publish any APK bytes.

Verified in a private offline inspection of the supplied APK (2026-11-04):

- SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`
- Size: 256,468,647 bytes; 7,368 ZIP entries; 6 DEX files.
- Native ABIs include ARM64 and ARMv7; `libunity.so` and `libil2cpp.so` present.
- `assets/bin/Data/Managed/Metadata/global-metadata.dat` has valid IL2CPP magic and metadata version 31.

These observations **do not** establish packet framing, handshake, login protocol, server address, or APK compatibility. Do not commit the APK, extracted libraries, asset files, credentials, endpoint strings, or proprietary code. A later evidence matrix must cite local class/method or native offsets, record tool versions and distinguish observed facts from hypotheses. Any protocol fixture checked into the public repository must be synthetic or reviewed for disclosure safety.

Next: inventory the transport entry points with offline JADX and IL2CPP metadata tooling compatible with metadata version 31, then write evidence-gated codecs and synthetic protocol regression tests. Never contact production endpoints without authorization.
