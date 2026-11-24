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

The ordered helper-call summary also requires every target address to be
four-byte aligned and every label to be a non-empty built-in string. This
matches the stricter control-flow summary contract and prevents an
unaligned relocation target or empty label from being counted as a resolved
serializer helper.

This is input-boundary hardening only. It does not change the recorded APK
observations, make the linear sequence path-aware, resolve indirect calls, or
establish serializer field order, framing, handshake, login, or compatibility.


## Fresh offline revalidation — 2026-11-23

The unchanged Library APK was re-read in a private workspace. Its SHA-256
remained
`c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`;
the ZIP contained 7,368 entries and the full CRC pass reported no failing
member. The metadata member remained 26,021,348 bytes with IL2CPP magic
`0xfab11baf` and version 31.

A fresh bounded metadata/ELF registration pass reproduced these aggregate
results:

| Check | Result |
|---|---:|
| Metadata images | 165 |
| Metadata method definitions | 197,631 |
| Images matched to native codegen modules | 165 |
| Unmatched / mismatched images | 0 / 0 |
| Images with non-empty method-pointer tables | 161 |
| Relocation-backed executable method-pointer targets | 164,023 |

The allowlisted relevant module counts were also rechecked:

| Module | Method-pointer slots | Relocation-backed executable targets |
|---|---:|---:|
| `ScriptsAssembly.dll` | 56,481 | 49,971 |
| `ConvertedAssembly.dll` | 25,442 | 25,264 |
| `ResourceDispatcher.dll` | 2,970 | 2,217 |
| `NetworkBase.dll` | 18 | 17 |

The LoginRequest windows were independently disassembled with the local LLVM
AArch64 disassembler and direct `BL` targets were matched against the
relocation-backed metadata method-entry map. The previously recorded results
were reproduced: serializer 38 direct primitive-helper sites (19 Int, 16
String, 2 Long, 1 Boolean) in a 4,264-byte bounded window; deserializer 33
sites (14 Int, 16 String, 2 Long, 1 Boolean) in a 7,904-byte window.

The same bounded direct-call pass observed the following additional
transport-support callsites:

| Method window | Directly resolved calls observed |
|---|---|
| `Receiver.Cycle` (9,476 bytes) | 2 `SimpleDeserializer.deserializeInt`; 2 `ClientNetworkStreamBuffer.SetDataAvailable`; 2 `AbstractClientBuffer.Write`; 1 `ClientArrayUtils.ZipDecompress`; 1 `Receiver.GetHttpMessageResponse`; 1 `Receiver.ReadStreamBufferToEnd` |
| `Sender.Cycle` (7,600 bytes) | 2 `SimpleSerializer.serializeInt`; 1 `AbstractClientBuffer.Read`; 1 `ClientArrayUtils.ZipCompression`; 1 `ClientNetworkStreamBuffer.SetDataAvailable`; 2 `ClientStreamBuffer.Write` |

These are bounded linear direct-call observations, not path-sensitive
execution traces. In particular, they do not prove that compression is applied
to every message, that the Sender and Receiver use symmetric framing, or that
the two integer calls have matching semantics. The field-default record for
`NetworkSettings.HeaderLength` was present, but its raw metadata type indexes
were not resolved to a managed value; no effective HeaderLength value is
claimed.

No new numeric message ID, complete packet schema, handshake sequence,
LoginRequest field order, endpoint, or unchanged-APK compatibility result was
established. The real AOW transport adapter remains disabled until an
authorized, redacted client-to-server byte fixture and end-to-end local test
confirm the complete contract. The APK, native library, raw instructions,
addresses, packet bytes, and private symbols remain outside this repository.


## Exact LoginRequest control-flow path comparison — 2026-11-24

The redacted network-callsite tool now includes a bounded control-flow path
summary for the exact `LoginRequestSTSerializer.serialize` and
`LoginRequestSTDeserializer.deserialize` entrypoints. It uses metadata-backed
direct-call targets and keeps the LoginRequest pair separate from transport
roots. The report pairs the two methods only when each resolves uniquely;
otherwise it returns `unpaired_or_ambiguous`.

The paired comparison normalizes primitive helper names to their family
(`serializeInt` / `deserializeInt` → `Int`) and reports bounded path-shape
overlap, unresolved observations, and truncation. Conditional edges remain
possible rather than evaluated, simple paths are enumerated without unrolling
cycles, and truncated entry windows force a `partial` result.

This is a static CFG path-shape comparison, not symbolic execution, runtime
execution, getter-to-field mapping, payload order, field count, a wire schema,
or a handshake/login proof. `field_order_inferred` remains false. The new
capability is validated with synthetic metadata/ELF/instruction fixtures; it
does not claim a new APK disassembly or packet observation.
