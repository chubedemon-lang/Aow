# Offline APK evidence inventory

Run locally with an authorized APK (do not commit or upload the APK):

```sh
python tools/apk_evidence_inventory.py /private/path/to/aow.apk
python -m unittest discover -s tests
```

The utility reads the APK as a ZIP without extracting its contents or making network calls. Its output contains only SHA-256 of the whole file, file size, category counts, and explicit `protocol_verified: false`. It intentionally does **not** output file names, endpoints, strings, certificates, code, secrets or assets. The checksum is a provenance identifier, **not** evidence that the server understands the protocol.

Follow-up evidence work must remain offline: use JADX for DEX call chains and Ghidra for native code only when needed. Do not commit APK bytes, proprietary code, endpoints, secrets, or unredacted reports. Transport framing, handshake, packet IDs, and login remain **unknown** until supported by traceable authorized evidence. Never probe production servers.
