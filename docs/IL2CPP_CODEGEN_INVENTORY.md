# Offline IL2CPP codegen-module inventory

The local tool tools/il2cpp_codegen_inventory.py reads only the global metadata and arm64 libil2cpp.so members from an authorized APK. It does not extract files to disk, make network requests, or emit native addresses, relocation values, endpoints, packet payloads or proprietary assets.

Run:

    python tools/il2cpp_codegen_inventory.py /private/path/aow.apk --output /private/path/codegen-inventory.json

The parser is scoped to IL2CPP metadata version 31 and ELF64 little-endian AArch64 shared objects. It validates metadata image method ranges, discovers native codegen module records through relative relocations to exact image-name strings, checks native method-pointer counts against metadata method-definition counts, and counts relocation-backed method-pointer slots that target executable ELF sections.

## Current authorized APK result (2026-11-10)

APK SHA-256: c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e.

- Metadata version: 31; method definitions: 197,631; images: 165.
- Exact image-name matching resolves 165/165 native codegen modules.
- Sum of native method-pointer slots: 197,631, matching the metadata method-definition count.
- Relative-relocation-backed method-pointer slots: 164,023; all 164,023 targets fall in executable ELF sections.
- ScriptsAssembly.dll: 56,481 slots; 49,971 relocation-backed executable targets.
- ConvertedAssembly.dll: 25,442 slots; 25,264 relocation-backed executable targets.
- NetworkBase.dll: 18 slots; 17 relocation-backed executable targets.
- ResourceDispatcher.dll: 2,970 slots; 2,217 relocation-backed executable targets.

An earlier broad string-scan estimate of 164 modules was incomplete. Exact metadata image-name lookup supersedes it and resolves all 165 images, including the generated image.

This establishes a static mapping between metadata image method ranges and native codegen module pointer tables. It does not prove that every method has a unique direct body: non-relocated slots may be null, shared, or represented by another registration mechanism. It also does not establish wire bytes, message IDs, field serialization order, framing, byte order, handshake order, active transport, endpoint selection, or compatibility with a reconstructed server.

Keep the APK and detailed local disassembly private. Do not commit native binaries, extracted assets, raw pointer addresses, endpoint values, credentials, or packet captures.
