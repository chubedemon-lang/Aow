# AArch64 small-argument data-flow evidence

This tool performs a bounded, redacted static analysis of synthetic or
authorized offline AArch64 method windows. It is not an ABI proof, packet
decoder, serializer schema, or compatibility test.

## Control-flow model

The analyzer recognizes these intraprocedural control-flow instructions:

- B.cond, CBZ/CBNZ, and TBZ/TBNZ as two-way conditional branches;
- direct B as an unconditional branch;
- BR/RET and pointer-authenticated BRAA/BRAB/BRAAZ/BRABZ as bounded-window exits;
- unrecognized encodings in the D6/D7 branch-register major-opcode family as
  conservative terminal barriers (recognized BLR/PAC-call encodings are
  classified first and retain caller fallthrough);
- RETAA/RETAB, ERET/ERETAA/ERETAB and DRPS as terminal return/exception edges;
- BL/BLR and pointer-authenticated BLRAA/BLRAB/BLRAAZ/BLRABZ as calls that
  clobber caller-saved abstract registers.

Branch targets outside the bounded method window are exits. The fallthrough
path of a conditional branch remains reachable. Bytes after an unconditional
branch or return are not analyzed unless another in-window branch reaches
them.

The pass propagates the supported MOVZ/MOVN/MOVK, unshifted
64-bit/32-bit MOV-register alias, ORR (immediate) with Rn=ZR, ADD (immediate),
and unflagged SUB (immediate) operations. The ORR decoder follows the bounded
logical-immediate bitmask construction: it rejects reserved encodings, invalid
32-bit N bits, and any non-ZR source rather than guessing a register value.
ADD/SUB forms using register 31 as SP, and SUBS
flag-setting forms, are not modeled. W-register arithmetic is masked to 32
bits (and therefore zero-extends when later observed as an X-register value);
X-register arithmetic is masked to 64 bits. An unknown source invalidates only
the arithmetic destination. Unknown instructions clear the entire abstract
register state. A call clears the caller-saved registers modeled by this pass.

Constants cross a block boundary only when the destination block has exactly
one reachable predecessor whose start precedes it in the window. Multi-predecessor
joins and backedges start with an empty abstract state. This deliberately loses
some valid facts rather than merging uncertain register values or iterating
loops unsafely.

## Output and limits

Observations are emitted only for uniquely resolved direct BL targets whose
metadata-derived method labels match an explicit allowlist prefix. Exact values
above 0xffff are omitted. Callers may opt into `include_argument_classes=True`
to receive only coarse x0-x7 value classes: `zero`, `small_nonzero_16bit`,
`nonzero_32bit`, or `nonzero_64bit`. This permits a later offline pass to
notice that a wide constant reaches an allowlisted helper without publishing
the constant itself. Output includes the direct-call ordinal in byte order,
the relative basic-block index, the relative instruction index, the allowlisted
method label and any remaining small x0-x7 constants. Unreachable calls can
therefore create ordinal gaps. No native addresses, raw instructions, APK
bytes, endpoint values or packet data are emitted.

The method window is capped at 64 KiB. Indirect branch targets are not
resolved; supported BR/PAC-branch forms and unrecognized D6/D7
branch-register-family encodings terminate the bounded path. Recognized
BLR/PAC-call forms are classified before that conservative family barrier and
retain fallthrough after caller-saved state is cleared.
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

## Metadata target identity is fail-closed

Direct-call observations require a single ordered metadata association with a
canonical /pN parameter-count suffix. The analyzer preserves duplicate
associations instead of collapsing them with a set, rejects unordered or
malformed association collections, and matches allowlist prefixes only at an
exact namespace/type boundary. This prevents duplicate, malformed, or
near-match metadata labels from being promoted to a unique target. The
regression vectors are synthetic and do not establish any new AOW callsite.


## Input object trust boundary

The public analyzer entry point accepts only exact built-in `bytes` for the
instruction window, an exact built-in `dict` with exact built-in integer
target keys, and exact built-in tuple/list/set/frozenset prefix collections
containing exact built-in strings. Ordered target-label associations must be
exact built-in lists or tuples. Subclasses are rejected or left unresolved
before their overridden length, iteration, lookup, equality, or conversion
hooks can participate in analysis. This is defensive input validation for the
offline tool; it adds no APK, native-callsite, packet, or compatibility
evidence.
