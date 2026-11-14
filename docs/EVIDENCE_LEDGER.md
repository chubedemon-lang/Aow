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

## Verified metadata methods

The metadata-only manifest validator and the in-memory evidence registry use
one shared allowlist for records marked `verified`:

- `apk_zip_inventory`
- `jadx_offline`
- `il2cpp_offline`
- `authorized_local_test`

Descriptive method text remains acceptable for `unverified` observations,
but it cannot promote a record to `verified`. Synthetic-only tests, guesses,
web searches, and unapproved method labels must not unlock protocol evidence
gates. A passing metadata validator is bookkeeping only; it does not establish
wire compatibility or replace review of the underlying local evidence.

## Public metadata path redaction

The JSON metadata validator (`server/offline_protocol_evidence.py`) and the
in-memory registry (`server/protocol_evidence_registry.py`) reject absolute
POSIX paths, shell-home paths, Windows drive-rooted and single-rooted paths,
UNC paths, and parent-directory traversal using either slash convention in
public free-text fields and reproduction commands. The legacy
`server/evidence_ledger.py` also rejects absolute and traversing paths in
evidence references. This prevents public provenance records from exposing
private APK/capture workspace locations or pointing outside the repository.
Sanitized repository-local references such as `docs/PROTOCOL.md#framing`,
`tests/test_offline_protocol_evidence.py`, and `issue:2` remain valid. These
are conservative privacy guardrails, not complete data-loss-prevention scans.

References are short, sanitized locators, not extracted strings. Keep APK
bytes, decompiled code, IP addresses, secrets, packet captures, proprietary
assets, and unredacted logs outside this public repository.

For offline research: identify APK checksum and archive structure, then use
JADX for Java bootstrap and IL2CPP-specific analysis for native protocol
paths. Record tool versions and observations privately. Promote a candidate
only after a reproducible offline observation; never infer packet IDs or
framing from filenames or guessed names. No official-server probing.
