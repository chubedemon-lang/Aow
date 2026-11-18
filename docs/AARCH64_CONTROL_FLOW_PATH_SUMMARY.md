# Bounded AArch64 serializer control-flow paths

The native-method evidence tool now adds a bounded simple-path view beside
its existing intraprocedural basic-block summary. It is intended to make
branch-exclusive serializer helper observations easier to compare without
mistaking a linear instruction-address listing for an execution order.

## What the summary means

For each selected serializer/deserializer method window, the analyzer:

1. Builds the existing bounded basic-block graph from recognized AArch64
   conditional branches, direct branches, indirect branch observations and
   return instructions.
2. Starts at block zero and enumerates possible simple paths through the
   reported graph.
3. Preserves helper-call observations in block/instruction order on each path.
4. Labels each in-window successor edge as `conditional_taken`,
   `conditional_fallthrough`, `branch_target`, or `fallthrough`.
5. Keeps conditional-taken and fallthrough edges distinct even when both
   converge on the same destination block; path records therefore may share
   block indexes while carrying different edge sequences.
6. Records a back-edge as a `cycle` exit rather than unrolling it.
7. Stops after at most 64 paths or 256 blocks per path by default.
8. Refuses to enumerate when the basic-block report itself was truncated.

The JSON report adds `control_flow_path_*` fields, including each path's
block indexes, exit kind and helper-callsite observations. Each path-level
helper observation also retains its zero-based `instruction_index` within the
bounded method window, when that index is a non-negative built-in integer.
This lets reviewers distinguish repeated calls within one block without
publishing a native address or instruction word. When block instruction ranges
are present, every indexed callsite must fall inside its owning block and
indexes must be strictly increasing. A block cannot mix indexed and unindexed
observations. Legacy summaries that omit all callsite indexes remain accepted;
malformed indexed summaries are rejected rather than silently presenting a
misordered helper sequence.

## Interpretation limits

- Conditional edges are both treated as possible; branch conditions are not
  evaluated. The path's `edges` array preserves whether an in-window edge is
  the taken target or fallthrough; it does not evaluate the condition.
- When an older synthetic CFG fixture omits `successor_edges`, the path
  summary labels its edges generically as `successor` rather than inferring
  branch semantics. Explicit edge metadata is validated against the successor
  set before enumeration.
- A conditional target outside the bounded entry window is recorded as a
  separate branch-exit path while any in-window fallthrough path is retained.
- The analysis is intraprocedural and limited to the bounded entry window.
- Loops are not executed or unrolled. A detected back-edge is represented as
  a cycle exit.
- A cycle exit does not by itself mark path enumeration as truncated. Hitting
  the path-count or depth limit does; inspect `control_flow_paths_truncated`
  and `control_flow_path_depth_limit_count`.
- Indirect calls are included only when the existing relocation-backed
  analysis resolves them uniquely. Unknown or ambiguous targets remain
  unresolved.
- A reported simple path is a static CFG possibility, not proof that the path
  executes for a particular message, runtime state, or client version.
- The helper sequence is not a serializer field schema. Getter provenance,
  collection traversal, virtual dispatch, optionality and runtime conditions
  still require separate evidence.
- The path limit and depth limit can produce a partial report; check
  `control_flow_paths_truncated` and the path-analysis status before
  interpreting results.

## Validation

Synthetic-only regression tests cover mutually exclusive branch paths,
back-edge reporting, path-limit behavior, truncated CFG refusal and invalid
successor rejection:

```sh
python -m unittest discover -s tests -p 'test_il2cpp_native_method_evidence.py' -v
```

The analyzer can be run against an authorized APK held in a private local
workspace:

```sh
python -m tools.il2cpp_native_method_evidence /path/to/authorized.apk \
  --output /private/local/native-method-evidence.json
```

Keep the APK, native library and full report outside this public repository.
This enhancement adds no packet bytes, message IDs, endpoints, credentials,
wire schemas or APK compatibility claim. The real transport adapter remains
blocked until an authorized client-side fixture or local runtime trace
reproduces framing, handshake and login on the unchanged APK build.
