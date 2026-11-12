# AArch64 small-argument data-flow evidence

This tool performs a bounded, redacted static analysis of synthetic or
authorized offline AArch64 method windows. It is not an ABI proof, packet
decoder, serializer schema, or compatibility test.

## Control-flow model

The analyzer recognizes these intraprocedural control-flow instructions:

- B.cond, CBZ/CBNZ, and TBZ/TBNZ as two-way conditional branches;
- direct B as an unconditional branch;
- BR/RET and pointer-authenticated BRAA/BRAB/BRAAZ/BRABZ as bounded-window exits;
- RETAA/RETAB, ERET/ERETAA/ERETAB and DRPS as terminal return/exception edges;
- BL/BLR and pointer-authenticated BLRAA/BLRAB/BLRAAZ/BLRABZ as calls that
  clobber caller-saved abstract registers.

Branch targets outside the bounded method window are exits. The fallthrough
path of a conditional branch remains reachable. Bytes after an unconditional
branch or return are not analyzed unless another in-window branch reaches
them.

The pass propagates only the supported MOVZ/MOVN/MOVK, unshifted
64-bit/32-bit MOV-register alias, and ADD (immediate) operations. Unknown
instructions clear the entire abstract register state. A call clears the
caller-saved registers modeled by this pass.

Constants cross a block boundary only when the destination block has exactly
one reachable predecessor whose start precedes it in the window. Multi-predecessor
joins and backedges start with an empty abstract state. This deliberately loses
some valid facts rather than merging uncertain register values or iterating
loops unsafely.

## Output and limits

Observations are emitted only for uniquely resolved direct BL targets whose
metadata-derived method labels match an explicit allowlist prefix. Values above
0xffff are omitted. Output includes the direct-call ordinal in byte order,
the relative basic-block index, the relative instruction index, the allowlisted
method label and any remaining small x0-x7 constants. Unreachable calls can
therefore create ordinal gaps. No native addresses, raw instructions, APK
bytes, endpoint values or packet data are emitted.

The method window is capped at 64 KiB. Indirect branch targets are not
resolved; the supported BR/PAC-branch forms terminate the bounded path, while
BLR/PAC-call forms return to fallthrough after caller-saved state is cleared.
The analyzer classifies pointer-authenticated instruction encodings only; it
does not emulate pointer authentication. It does not evaluate branch
conditions, model register writes outside its small instruction subset,
resolve arbitrary exception edges, prove ABI argument semantics, or establish
the execution order of serializer fields. A reported xN value
is only a static abstract-register observation immediately before a uniquely
resolved callsite.

## Tests

tests/test_aarch64_call_argument_evidence.py uses fabricated instruction words
and synthetic relocation-backed method targets only. Positive and negative
fixtures cover supported pointer-authentication forms, nearby non-matching
encodings, and invalid input types. These tests verify conservative
classification only; they do not analyze the AOW APK or prove any AOW packet,
handshake, login field or wire format.


## Encoding references

The branch/call and pointer-authentication instruction masks are cross-checked
against the GNU binutils AArch64 opcode table and an A64 instruction reference.
These references support instruction classification only; they do not establish
that any such instruction occurs in the AOW APK.

- [GNU binutils AArch64 opcode table](https://gnu.googlesource.com/binutils-gdb/+/7e8d2d875701971c77224079056a0c8272d63109/opcodes/aarch64-tbl.h)
- [A64 instruction reference](https://shell-storm.org/armv8-a/)
