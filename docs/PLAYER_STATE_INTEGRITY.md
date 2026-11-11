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

## Creation baseline receipts and legacy migration

New snapshots are written with a `baseline_version=1` marker and a matching row in `player_state_creations`, in the same transaction as the initial snapshot. The read-only audit requires that receipt, checks its value ranges, and replays every later mutation from the recorded level/experience/currency baseline. A missing or altered baseline receipt therefore fails the audit instead of silently treating the first mutation as the starting point.

Existing databases are migrated additively: the new marker is added with value `0`, and old snapshots remain readable as `legacy_unanchored_snapshots`. Their mutation deltas and later revision chain are still checked, but their original level cannot be independently reconstructed. New snapshots created after migration are anchored.

The marker and receipts improve consistency detection; they are not cryptographic tamper evidence. An attacker able to rewrite the snapshot, marker, creation receipt and all mutation receipts can rewrite them together. Protect the database file and backups with operating-system access controls.
