# Synthetic inventory integrity audit

`SqliteInventoryStore.verify_integrity()` performs a read-only audit of the synthetic inventory tables. It does not define AOW item IDs, item stacks, equipment, capacity, or wire messages.

## Creation baseline

New inventory snapshots are created empty at revision zero. Creation now stores a canonical revision-zero baseline receipt in `inventory_creations` and marks the snapshot with `baseline_version=1` in the same transaction.

The audit requires the marker and receipt to agree, validates the receipt's character, capacity, stack limit and empty item list, then replays every mutation from that independent empty baseline. A missing, altered or orphaned creation receipt fails closed. Snapshot creation and its baseline receipt are atomic, including when called inside a caller-owned transaction.

## Legacy databases

The migration adds `baseline_version` with default `0` and creates the receipt table without inventing history for existing rows. Legacy snapshots remain explicitly unanchored. Their first mutation is checked using the prior inverse-delta method, and later mutations are replayed normally. Audit output reports both `anchored_snapshots` and `legacy_unanchored_snapshots`.

The read-only audit accepts the pre-migration schema only when both the marker column and creation table are absent. A partially applied or malformed creation schema is rejected. The audit never performs a migration or repair.

## Limits

These receipts improve consistency detection; they are not cryptographic tamper evidence. An actor able to rewrite the snapshot, marker, creation receipt and all mutation receipts can rewrite them together. Protect the database and backups with operating-system access controls.

All identifiers, capacities, stack limits and item deltas remain synthetic operator-supplied values. This change does not establish any AOW inventory contract or APK compatibility.
