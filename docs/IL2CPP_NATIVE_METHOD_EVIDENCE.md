# Native method entry-point evidence (offline)

**Date:** 2026-11-10  
**Input:** user-provided AOW APK, inspected read-only in a private workspace  
**Compatibility status:** not established

## Reproduction

Run the allowlisted analyzer locally:

```bash
python tools/il2cpp_native_method_evidence.py /private/path/aow.apk \
  --output /private/path/network-method-evidence.json
```

The tool reads only the IL2CPP v31 metadata member and arm64 `libil2cpp.so`
from the APK. It reuses the bounded metadata/ELF parser in
`tools/il2cpp_codegen_inventory.py`. It emits method names, parameter counts,
image names and relocation status only. It does not emit native addresses,
relocation addends, raw instructions, endpoints, packet bytes or assets.

## Result for the inspected APK

- APK size: 256,468,647 bytes.
- SHA-256: `c00bd00d30f625b85dfcc0159b3b058ca459c10f9917844a5301163480c7624e`.
- IL2CPP metadata version: 31.
- Metadata method definitions: 197,631.
- Allowlisted network methods observed: 20.
- Methods with a relative-relocation-backed pointer into an executable section: 19.
- One `MessageHelper.GetMessageType` overload (zero parameters) has no
  `R_AARCH64_RELATIVE` entry at its codegen slot. This does not prove that the
  overload has no implementation; it may use shared, null, or another
  registration path.

The 19 executable-entry records are in the ELF `.il2cpp` section and cover:

- `NetworkSocketStream.Read/Write`;
- `Network.ConnectBeginAsync`, `SendMessage` and received-message processing;
- `NetworkSettings` static initializer and constructor;
- `Receiver` cycle, stream callback and buffer/HTTP helper methods;
- `Sender` cycle, heartbeat and serialization test methods;
- `MessageDispatcher.Dispatch/TypeRegister`;
- `MessageHelper.InternalGetMessageType` and one `GetMessageType` overload.

## Static disassembly observations

A private, read-only spot-check of the resolved native entries shows:

- `NetworkSocketStream.Read` and `Write` dispatch to the wrapped stream object.
- `Network.SendMessage` follows message-metadata and serializer-related
  indirect-dispatch paths.
- `Network.ProcessingOneReceivedMessage` invokes `MessageDispatcher.Dispatch`.
- `Receiver.Cycle` calls the receiver's HTTP-response and stream-buffer helper
  methods in addition to its stream-processing path.

These are method-body observations from this build, not proof that a particular
path is active in every session. The current analysis has **not** established
how `NetworkSettings.HeaderLength` is consumed, the exact frame layout,
byte order, compression/encryption activation, message IDs on the wire,
serializer field order, handshake sequence or login semantics.

## Interpretation and limits

This is stronger than a metadata-name inventory: it associates selected
metadata methods with relocation-backed executable native entry points. It is
still not a recovered wire protocol. A method pointer alone does not establish
the method's full semantics, runtime reachability, or client/server compatibility.

No packet fixtures were fabricated. No endpoint was contacted and no official
server infrastructure was accessed. The APK, native binaries, detailed local
disassembly and proprietary assets remain outside this public repository.

## Next evidence required

Continue tracing the native read/write call path and the actual use of
`HeaderLength`, then follow the login serializer/deserializer. A real protocol
adapter remains blocked until an authorized test-client log or redacted packet
fixture can reproduce the byte stream. Keep synthetic framing explicitly
separate from the AOW wire contract.
