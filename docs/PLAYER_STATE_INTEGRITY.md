# Synthetic player-state integrity audit

SqlitePlayerStateStore.verify_integrity() performs a read-only audit of the synthetic player-state tables.

It checks:

- SQLite quick_check and foreign_key_check;
- stored snapshot value ranges and revisions;
- that every mutation belongs to an existing snapshot;
- that mutation revisions form a contiguous chain beginning at revision 1;
- that each receipt's requested level and experience/currency deltas reproduce the next result;
- that the final receipt matches the current snapshot, and that an untouched snapshot remains at revision 0.

The audit requires an idle connection and never repairs data. It is intended for local preflight, diagnostics and tests; it does not establish any AOW progression rules or wire fields.

## Baseline limitation

The current schema does not store a separate receipt for create(). Therefore the audit can validate revision zero and every subsequent mutation chain, but cannot independently prove the original level/experience/currency baseline against an attacker who can rewrite both the initial state and all dependent receipts. If a first mutation overrides level, the original level is not recoverable from that receipt; the resulting level is checked against the requested override.

This is a consistency check, not a cryptographic tamper-evidence system or production database security boundary.
