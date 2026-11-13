# Connection-bootstrap dispatcher registration evidence — 2026-11-12

**Scope:** authorized, read-only static inspection of the original Android APK in a private local workspace. The APK was not modified. No server endpoint was contacted.

## Fresh offline integrity check

- APK size: `256468647` bytes.
- APK SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`.
- ZIP entries: `7368`; a full CRC test reported no failing entry.
- IL2CPP metadata: version `31`, `26021348` bytes.
- ARM64 native library: ELF64, little-endian, AArch64, `166150720` bytes.
- The fresh metadata/codegen pass matched the known 165-image/197,631-method-slot inventory. Raw native addresses and instruction bytes remain private.

## New client-side registration observation

The metadata-backed state-machine method `<StartConnectToServer>d__12.MoveNext` contains two direct calls to `MessageDispatcher.SafeRegister`. At those two callsites, the second integer argument is loaded as the small constants **5004** and **5005**, respectively. Each registration is preceded by construction of an `OnMessageReceivedDelegate` instance.

The native `SafeRegister` body forwards the supplied integer key into `MessageDispatcher.TypeRegister` and updates its listener-registration collection. This supports the interpretation that 5004 and 5005 are **client-side dispatcher registration keys** in the connection-start path.

### Explicit limits

- These values are **not confirmed wire message IDs**. No packet capture or runtime trace links either key to bytes received from or sent to a server.
- The delegate target metadata references are not yet resolved to unique callback method names; no message class names are assigned to the two keys.
- The second `deserializeInt` result in `Receiver.Cycle` is passed as a key to a subsequent lookup/dispatch path, but the target is not yet uniquely resolved to a metadata method. Treat it as a candidate message discriminator, not a verified wire ID.
- `NetworkSettings.HeaderLength` exists in metadata, but this pass did not establish a data-flow link from that field to the immediate four-byte receive count. Do not equate the field with the observed read size.
- `Sender.Cycle` still has two `serializeInt` callsites around compression and two stream writes; their individual semantics remain unresolved.

## Analyzer change

The redacted network-callsite inventory now explicitly includes the narrow connection-start state-machine root, `MessageDispatcher.SafeRegister`, and the delegate constructor. It reports small argument constants only at uniquely resolved allowlisted calls; it does not emit native addresses, instruction bytes, packet bytes or endpoint values.

Synthetic tests verify that the new roots are selected and that two small registration-key arguments can be reported without exposing code addresses. They do not prove that the values are wire IDs or that the APK can connect to the reconstructed server.

## Next proof gates

1. Resolve the two delegate callback targets through the native metadata-usage/generic-method path.
2. Trace the receiver's second integer through the exact lookup and dispatch target.
3. Correlate client-side registration keys with authorized, redacted client-side wire fixtures before assigning wire message IDs.
4. Continue tracing the sender's two integer writes and the effective `NetworkSettings.HeaderLength` use.
5. Keep the transport adapter disabled until framing, handshake, LoginRequest and end-to-end behavior are independently verified.

No APK, native library, raw instruction bytes, packet capture, endpoint value, credential, player data or proprietary asset is included in this repository.


## Fresh private revalidation — 2026-11-13

The same authorized APK fingerprint was re-read in the isolated workspace and matched the existing ledger. The full bounded ZIP CRC pass succeeded. The metadata/codegen inventory again matched 165/165 images and 197,631/197,631 method-pointer slots.

A fresh bounded CFG analysis of the connection-start state-machine entrypoint resolved two direct calls to `MessageDispatcher.SafeRegister`. The second integer argument in x1 was 5004 at one callsite and 5005 at the other.

These observations reconfirm the two values as **client-side dispatcher registration keys**. They are still not wire message IDs: no authorized packet bytes or runtime trace links either key to a transmitted message. Callback target metadata references remain unresolved. Do not assign message names or build a wire dispatch table from these values alone.

The receiver and sender entrypoint windows also retain two direct primitive integer helper callsites each (two `deserializeInt` calls in `Receiver.Cycle`, two `serializeInt` calls in `Sender.Cycle`). Their individual semantics and full control-flow relationship remain unresolved.


## Dispatcher listener delegate metadata — 2026-11-13

A fresh offline read of the authorized APK's IL2CPP v31 metadata was used to
extend the allowlisted type inventory. The new inventory output is limited to
type/field/method names, parameter names, metadata tokens and raw type indexes;
it does not emit native addresses, instruction bytes or binary assets.

The metadata associates these declarations:

- `MessageDispatcher.SafeRegister` and `TypeRegister` each declare two
  parameters named `type` and `listener`.
- `OnMessageReceivedDelegate` declares a constructor with parameters
  `object` and `method`, plus an `Invoke` method with one parameter named
  `message`.
- The global `OnMessageReceivedDelegateData` type declares a field named
  `Delegate`.
- `MessageDispatcher` declares listener-related fields
  `m_listeners`, `m_listenersByType`, `m_globalMessageHandlers`,
  `m_unhandledMessageHandlers`, and a field named
  `m_lastProcessedServerSequenceNumber`.

These are metadata declarations only. The raw type indexes have not been
resolved to full managed type names in this pass, and the native delegate
constructor callsites have not yet been connected to unique callback method
targets. This does not identify which callback handles registration keys
5004 or 5005, nor does it prove that either key is a wire message ID.

The offline type inventory now includes `OnMessageReceivedDelegate` and
`OnMessageReceivedDelegateData` in its allowlist. Synthetic tests verify
that the method/field/parameter associations are retained without assigning
callback or wire semantics.

### Next analysis step

Resolve the `object` and `method` arguments at each native delegate
constructor callsite in `<StartConnectToServer>d__12.MoveNext`, then map
each target against unique metadata-backed executable method entries. Keep
unresolved and ambiguous targets explicitly unresolved.


## Delegate method-pointer analyzer tooling — 2026-11-13

A new bounded CFG pass in `tools/aarch64_delegate_target_evidence.py` is integrated into the redacted native callsite inventory. It follows only ADR/ADRP, 64-bit ADD-immediate, relocation-backed LDR X, and unshifted MOV X copies before the allowlisted `OnMessageReceivedDelegate::.ctor` callsites. The configured x2 value is treated only as a candidate for the second declared constructor parameter.

The report emits a unique metadata-backed method label only when the tracked pointer exactly matches one executable method entry. Missing, ambiguous, unsupported, or thunk-like values remain unresolved. Raw pointer values, native addresses and instruction bytes are never emitted. The pass drops state at joins/backedges, clobbers caller-saved registers at calls, and clears state on unknown instructions.

Synthetic tests use fabricated instruction words and relocations. **This PR does not run the analyzer against the APK and adds no callback target result.** It does not identify message IDs, map keys 5004/5005 to wire traffic, or prove handshake/login compatibility. See [AArch64 delegate method-pointer evidence](AARCH64_DELEGATE_TARGET_EVIDENCE.md).
