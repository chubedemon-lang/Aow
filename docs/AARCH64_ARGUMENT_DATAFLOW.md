# AArch64 small-argument data-flow evidence

This tool performs a bounded, redacted static analysis of synthetic or
authorized offline AArch64 method windows. It is not an ABI proof, packet
decoder, serializer schema, or compatibility test.

## Control-flow model

The analyzer recognizes these intraprocedural control-flow instructions:

- B.cond, CBZ/CBNZ, and TBZ/TBNZ as two-way conditional branches;
- direct B as an unconditional branch;
- BR and RET as bounded-window exits;
- BL and BLR as calls that clobber caller-saved abstract registers.

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

The method window is capped at 64 KiB. This analysis does not evaluate branch
conditions, model register writes outside its small instruction subset, follow
indirect control flow, resolve exception edges, prove ABI argument semantics,
or establish the execution order of serializer fields. A reported xN value
is only a static abstract-register observation immediately before a uniquely
resolved callsite.

## Tests

tests/test_aarch64_call_argument_evidence.py uses fabricated instruction words
and synthetic relocation-backed method targets only. These tests verify the
analyzer's conservative behavior; they do not analyze the AOW APK or prove
any AOW packet, handshake, login field or wire format.
