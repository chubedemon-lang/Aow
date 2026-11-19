# AArch64 immediate call-result branch evidence

This bounded analyzer identifies one narrow instruction pattern in a supplied
AArch64 method window:

1. A direct `BL` or recognized indirect `BLR` call.
2. The immediately following instruction is `CBZ` or `CBNZ` testing
   `W0` or `X0`.

Under the AArch64 procedure-call convention, register X0/W0 is also the first
scalar result register. Because the branch is adjacent to the call, there is
no intervening instruction in the supplied window that can overwrite it. The
tool reports this only as an **immediate call-result register-use candidate**.

## Output

The report contains relative call and branch instruction indexes, direct or
indirect call class, tested register, zero/nonzero branch condition, relative
branch-target index when inside the bounded window, aggregate counts and an
explicit truncation flag. No native address, instruction word, APK byte,
callee name, packet field or message value is emitted.

## Interpretation limits

- The scan is linear; it does not evaluate the CFG or runtime conditions.
- It does not resolve the call target or infer the callee's managed return
  type. A post-call test of W0/X0 is consistent with consuming a scalar result,
  but is not proof that the callee returns a boolean.
- It does not prove the call or branch executes for a particular input.
- It does not identify a HashSet owner, compression decision, message ID,
  frame field, handshake stage, login schema or APK compatibility.
- Only an immediately adjacent CBZ/CBNZ on W0/X0 is reported. CMP/TST,
  TBZ/TBNZ, register copies, other registers and more distant data-flow remain
  unresolved rather than guessed.
- Synthetic instruction tests validate the decoder only. No AOW APK analysis
  is claimed by adding this tool.

Run:

```sh
python -m unittest discover -s tests -p 'test_aarch64_call_return_evidence.py' -v
```

Keep authorized APKs and native libraries in a private offline workspace.
