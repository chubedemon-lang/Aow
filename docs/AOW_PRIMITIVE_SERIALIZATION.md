# AOW primitive serialization evidence

**Date:** 2026-11-10  
**Input:** authorized, user-provided APK; inspected read-only in a private workspace  
**Status:** static native evidence; not an end-to-end wire contract

## Observed native call path

The offline IL2CPP analyzer maps the primitive helper methods in
`com.geargames.serialization.SimpleSerializer` and
`SimpleDeserializer` to relocation-backed executable entries. A bounded
AArch64 callsite report maps direct helper calls without emitting addresses or
instructions.

The private method-body spot-check establishes these relationships:

- `serializeInt` calls `serializeChar` with the high 16-bit half, then tail-branches with the low half.
- `serializeLong` calls `serializeChar` four times, from most-significant to least-significant 16-bit chunk.
- `deserializeInt` reads two `deserializeShort` values and places the first in the high 16 bits.
- `deserializeLong` reads two 32-bit values, high half first.
- `serializeChar` passes the high byte and then low byte to the virtual writer; `deserializeChar`/`deserializeShort` read two bytes and combine them high-first.
- `serializeString` writes a 16-bit code-unit length and then serializes each .NET string character. Null uses `0xFFFF`; lengths `>= 0x8000` are rejected.
- `deserializeString` interprets a 16-bit length with bit 15 set as null and otherwise reads the specified number of UTF-16 code units.
- `serializeBoolean` writes the low bit as one byte; `deserializeBoolean` is true only for byte value `1`.

## Server implementation

`server/aow_primitive_codec.py` implements only these primitive operations:

- unsigned byte;
- boolean;
- 16-bit char and signed short;
- signed 32-bit integer;
- signed 64-bit integer;
- nullable UTF-16BE string with the observed 16-bit length behavior.

The module is intentionally isolated and is not connected to any network handler.
It must not be used to claim that AOW framing, message IDs, payload field order,
compression/encryption, handshake or login have been recovered.

The reader exposes its current payload offset and a `require_consumed()`
guard. A caller may use that guard only after it already knows the exact
payload schema and boundary; the method does not discover a packet frame or
prove that a byte sequence belongs to one AOW message.

## Validation

The codec has synthetic known-vector tests for big-endian values, signed
round-trips, null/empty strings, UTF-16 surrogate pairs, the 32767-code-unit
limit, boolean semantics, truncation, invalid values and exact payload
consumption. No APK, native binary, address, raw instruction, endpoint or
packet capture is committed.
