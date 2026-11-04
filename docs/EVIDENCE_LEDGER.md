# Offline protocol evidence ledger

`server/evidence_ledger.py` tracks **sanitized** evidence status; it is not
a protocol decoder and does not claim original APK compatibility.

- `unknown`: not established.
- `candidate`: hypothesis awaiting validation.
- `verified_offline`: backed by authorized local APK analysis.
- `verified_end_to_end`: supported by an authorized test with the unchanged
  original APK against a locally controlled server.

Only the last category can satisfy `protocol_ready`, and all four required
topics (transport, framing, handshake, login) must have independent records.
The status gate is bookkeeping, **not** proof by itself; reviewers must inspect
the underlying authorized evidence before approving a compatibility claim.

References are short, sanitized locators, not extracted strings. Keep APK
bytes, decompiled code, IP addresses, secrets, packet captures, proprietary
assets, and unredacted logs outside this public repository.

For offline research: identify APK checksum and archive structure, then use
JADX for Java bootstrap and IL2CPP-specific analysis for native protocol
paths. Record tool versions and observations privately. Promote a candidate
only after a reproducible offline observation; never infer packet IDs or
framing from filenames or guessed names. No official-server probing.
