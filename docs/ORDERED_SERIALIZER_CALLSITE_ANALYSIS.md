# Ordered serializer helper callsite analysis

The offline IL2CPP native evidence report now includes
`linear_helper_callsite_order` for each bounded login/session serializer
entry window.

The sequence interleaves uniquely resolved:

- direct `BL` calls to allowlisted primitive serializer/deserializer helpers;
- relocation-backed indirect `BLR` calls;
- direct `B` tail calls to allowlisted helpers; and
- relocation-backed indirect `BR` tail calls.

Each resolved entry contains only a call kind and a metadata-derived helper
label. Indirect sites that cannot be resolved to an allowlisted helper are
represented as `not_resolved_as_serializer_helper`; ambiguous helper targets
are explicitly marked ambiguous. Native addresses and instruction words are
not emitted.

## Interpretation limits

This is **linear static callsite order within a bounded method window**, not
an execution trace or recovered field order. The scanner does not evaluate
conditional branches, loops, exception paths, register liveness across full
control-flow graphs, or mutually exclusive paths. A listed callsite may be
on a branch that is not executed for a particular message. Unknown instructions
still invalidate the conservative indirect-register state.

Use this sequence only to prioritize private offline review of serializer
paths. A field-order claim still requires control-flow and data-flow
confirmation, serializer/deserializer correlation, and preferably an
authorized redacted local fixture. The addition itself does not run the APK,
produce packet bytes, prove message IDs, framing, handshake, login, or
client/server compatibility.

The tests use synthetic AArch64 instruction vectors and synthetic relocation
maps only. No APK, native library, endpoint, raw capture, native address, or
proprietary asset is committed.


## Control-flow-aware basic-block summary

Each bounded login/session serializer window also receives a
control_flow_basic_blocks summary. The analyzer recognizes AArch64 B.cond,
CBZ/CBNZ, TBZ/TBNZ, direct B, relocation-backed BR, and RET terminators. It
groups helper callsites by basic block and marks blocks reachable from the
entry block through the conservative intraprocedural CFG.

Both outcomes of a conditional branch are considered possible. A branch that
leaves the bounded method window is represented only as an exit; the analyzer
does not follow another function or guess an external destination. An
unresolved indirect branch is also an exit. The summary reports relative
instruction indices and metadata-derived helper labels only, never native
addresses or instruction words. Reports are capped at 512 blocks per method
window and disclose truncation.

This avoids presenting mutually exclusive callsites from separate branches as
one apparent serializer sequence, and distinguishes unreachable bytes after
an unconditional branch from reachable code. It still does not evaluate
conditions, loops, register state at merge points, exception edges, or runtime
paths. Reachability means graph reachability under the decoded branch subset,
not proof that a branch executes. A field-order claim still requires full
control/data-flow review, serializer/deserializer correlation, and preferably
an authorized redacted local fixture.
