# Login and session-restore linear callsite evidence

**Scope:** fresh authorized, read-only offline inspection of the unchanged APK in a private workspace. The APK and native library remain outside this repository. No endpoint was contacted. This note adds a redacted static callsite observation; it is not a wire schema.

## Revalidation basis

- The APK fingerprint matched the existing private inventory recorded in `docs/NATIVE_NETWORK_CALLSITE_EVIDENCE.md`.
- The full ZIP CRC check passed; the archive had 7,368 entries and no duplicate names.
- IL2CPP metadata v31 was re-read. The 165 metadata images again matched 165 native codegen modules; 161 modules had non-empty method-pointer tables, and 164,023 method-pointer slots had relative-relocation-backed executable targets.
- Method entry windows were bounded at the next distinct relocation-backed executable entry in the same ELF section, with the existing 64 KiB maximum. They are not formal function boundaries.

## Direct primitive-helper callsite signatures

A private scan resolved direct AArch64 `BL` destinations to unique metadata-backed `SimpleSerializer` / `SimpleDeserializer` entrypoints. The sequence below is run-length encoding of **linear instruction-address order** in each bounded window. `Int`, `String`, `Long`, and `Boolean` name only the primitive helper family.

| Method | Window | Direct helper sites | Counts |
|---|---:|---:|---|
| `LoginRequestSTSerializer.serialize` | 4,264 bytes | 38 | 19 Int, 16 String, 2 Long, 1 Boolean |
| `LoginRequestSTDeserializer.deserialize` | 7,904 bytes | 33 | 14 Int, 16 String, 2 Long, 1 Boolean |
| `SessionRestoreRequestSTSerializer.serialize` | 976 bytes | 7 | 5 Int, 2 String |
| `SessionRestoreRequestSTDeserializer.deserialize` | 1,432 bytes | 6 | 4 Int, 2 String |

### LoginRequest direct-call sequence

- Serializer: `Int×6 → String×2 → Int → String×6 → Int×2 → String → Int → String×2 → Long → Boolean → Long → String → Int×6 → String×3 → Int×2 → String → Int`.
- Deserializer: `Int×6 → String×2 → Int → String×6 → Int×2 → String → Int → String×2 → Long → Boolean → Long → String → Int×3 → String×3 → Int → String`.

### SessionRestoreRequest direct-call sequence

- Serializer: `Int×2 → String → Int×2 → String → Int`.
- Deserializer: `Int×2 → String → Int×2 → String`.

## Interpretation limits

These are direct-callsite observations only. They are not runtime execution counts, field counts, field order, a reconstructed message schema, or proof that all sites execute on one path. Bounded windows may contain cold code, shared code, loops, mutually exclusive branches, and instructions after an early return. Ordinary virtual `BLR` calls are not attributed by this direct-only scan; unresolved and indirect calls are not silently assigned helper names.

In particular, the differing LoginRequest integer call counts (19 serializer versus 14 deserializer) remain unexplained. The sequences do not identify which getter or collection element feeds a helper. No wire message ID, packet boundary, handshake/authentication order, LoginRequest field order, or APK/server compatibility is inferred.

## Next proof step

Resolve the remaining indirect calls and their receiver/argument provenance, then associate any proven getter or collection traversal with the LoginRequest metadata fields. Only after that should a candidate field order be compared with an authorized, redacted client-side byte fixture. Keep the real APK transport adapter disabled until framing, handshake, login and unchanged-APK end-to-end behavior are independently verified.

No APK, native library, asset, raw address, instruction word, packet byte, endpoint, credential, or player data is included here.

## Direct linear callsite analyzer input boundary

The redacted direct-call summary now accepts only exact built-in `bytes` for
the bounded instruction window and an exact built-in `dict` for helper
targets. Target keys must be non-negative, four-byte-aligned built-in
integers; each target value must be a built-in list or tuple containing only
non-empty built-in strings. This prevents custom Python container hooks from
participating in instruction decoding or label lookup.

This is input-boundary hardening only. It does not change the recorded APK
observations, make the linear sequence path-aware, resolve indirect calls, or
establish serializer field order, framing, handshake, login, or compatibility.
