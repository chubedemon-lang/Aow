# AArch64 immediate call-result branch evidence

This bounded analyzer identifies two narrow instruction patterns in a
supplied AArch64 method window:

1. A direct `BL` or recognized indirect `BLR`, immediately followed by
   `CBZ` or `CBNZ` testing `W0` or `X0`.
2. A direct `BL` or recognized indirect `BLR`, immediately followed by
   `CMP W0, #0` or `CMP X0, #0`, then immediately followed by
   `B.EQ` or `B.NE`.

Under the AArch64 procedure-call convention, register X0/W0 is also the first
scalar result register. In the second pattern, the adjacent compare consumes
that register and the adjacent conditional branch consumes the flags produced
by the compare. No intervening instruction in the supplied window can
overwrite the result register or those flags. The tool reports both patterns
only as **call-result dependency candidates**.

## Output

The report contains relative call, compare and branch instruction indexes,
direct or indirect call class, tested register, zero/nonzero branch condition,
relative branch-target index when inside the bounded window, aggregate counts
and explicit truncation flags. The legacy CBZ/CBNZ fields remain unchanged;
the CMP/B.cond pattern has separate `immediate_cmp_zero_bcond_count` and
`cmp_zero_bcond_observations` fields. No native address, instruction word,
APK byte, callee name, packet field or message value is emitted.

## Interpretation limits

- The scan is linear; it does not evaluate the CFG or runtime conditions.
- It does not resolve the call target or infer the callee's managed return
  type. A post-call test of W0/X0 is consistent with consuming a scalar result,
  but is not proof that the callee returns a boolean.
- It does not prove the call or branch executes for a particular input.
- It does not identify a HashSet owner, compression decision, message ID,
  frame field, handshake stage, login schema or APK compatibility.
- Only the two exact shapes above are reported. TST, TBZ/TBNZ, register
  copies, other registers, nonzero CMP immediates and more distant data-flow
  remain unresolved rather than guessed.
- Synthetic instruction tests validate the decoder only. No AOW APK analysis
  is claimed by adding this tool.

Run:

```sh
python -m unittest discover -s tests -p 'test_aarch64_call_return_evidence.py' -v
```

Keep authorized APKs and native libraries in a private offline workspace.
