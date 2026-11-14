# Durable synthetic map-position store

## Scope

This module persists the repository's synthetic MapPosition domain object. It is an independent server persistence primitive, not an AOW map ID catalog, coordinate system, movement packet, collision model, or client contract.

Map IDs and coordinate values are supplied by the caller. The module does not authenticate a character, prove session ownership, or expose an HTTP route.

## Operations

SqliteMapPositionStore supports:

- create(character_id): create an unplaced snapshot at revision 0.
- enter(character_id, request_id, expected_revision, map_id, x, y): enter one synthetic map from the unplaced state.
- move(character_id, request_id, expected_revision, map_id, x, y): update a position only when the current map matches the supplied map ID.
- leave(character_id, request_id, expected_revision, map_id): leave only the currently occupied map.
- get(character_id): read the durable immutable snapshot.
- verify_integrity(): run SQLite quick/foreign-key checks and replay every transition receipt against the current snapshot without repairing or mutating data. The audit requires an idle connection, opens one deferred read transaction for a consistent snapshot, and always rolls it back on success or failure.

Every successful transition increments the revision exactly once.

## Transaction and retry semantics

Each transition and its receipt are committed in one SQLite BEGIN IMMEDIATE transaction. A request ID is globally unique within this store:

- An exact retry returns the original committed snapshot, even if later transitions have advanced the current state.
- Reusing a request ID for another character, operation, expected revision, map, or coordinate is rejected.
- A stale revision, invalid map transition, or mismatched map ID leaves both the snapshot and receipt table unchanged.
- Separate SQLite connections serialize standalone writers; tests cover duplicate and competing concurrent requests.
- Nested operation failures are isolated by savepoints, so a failed snapshot/receipt pair cannot leave a partial position update in the caller's transaction.

The connection is supplied by the caller and remains caller-owned.

## Integrity audit

`verify_integrity()` checks SQLite page integrity and foreign-key consistency, validates bounded receipt JSON without duplicate keys or non-finite values, replays enter/move/leave transitions in revision order, and compares the reconstructed result with every stored receipt and current snapshot. It detects missing receipts, revision gaps, tampered payload/result snapshots, and orphaned mutation rows. It is diagnostic only: it never repairs data and does not authenticate character ownership.

## Validation

Run the focused suite:

    python -m unittest tests.test_sqlite_map_position_store -v

The repository-wide GitHub Actions suites also run on pull requests.

## Explicit non-goals

This store does not establish AOW map identifiers, coordinate units, spawn rules, movement speed, collision/bounds, map transfer semantics, wire serialization, packet framing, or APK compatibility. It must not be treated as evidence for the original game's protocol. A future verified adapter must authenticate and authorize character ownership before invoking this domain store.

## Large-history audit behavior

The integrity audit iterates the snapshot and mutation query cursors directly. It does not call `fetchall()` on either potentially large map-position table, avoiding a second in-memory copy of the full serialized receipt history. Both scans remain inside the same deferred read transaction. The audit still retains per-character state required to replay revision chains, so memory usage grows with the number of characters rather than with the complete receipt payload history.

A regression test uses a SQLite connection/cursor guard that raises if either map-position table query is materialized with `fetchall()`. All data in that test is synthetic and does not establish AOW wire compatibility.
