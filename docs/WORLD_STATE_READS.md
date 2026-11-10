# Authorized synthetic world-state snapshots

**This is a local persistence/domain integration, not an AOW player-init or
map-join wire contract.**

SqliteAuthorizedWorldStateService reads the owned character row, durable
player snapshot and durable map-position snapshot inside one BEGIN IMMEDIATE
transaction.

The service also provides enter_and_get_snapshot,
move_and_get_snapshot and leave_and_get_snapshot. Each operation:

- validates the durable session and character ownership first;
- applies the map-position transition using the caller's expected revision;
- reads the character, player and map records from the same SQLite connection;
- commits the transition, its idempotency receipt and the returned world view
  in one transaction;
- serializes with session revocation and other protected writes;
- rolls back the movement and receipt if authorization or a snapshot read fails.

An idempotent retry returns two intentionally distinct values:
- the mutation receipt contains the original result of that request;
- the world snapshot contains the latest committed state at the time of retry.

This prevents an old request replay from making a caller mistake historical
receipt data for the character's current position.

A missing player or map snapshot fails closed. Reads and movement operations do
not create missing per-character snapshots or repair incomplete state.

## Scope

All values remain synthetic. Map identifiers, coordinate units, movement
rules and transition semantics are placeholders for local persistence tests.
This service does not define AOW character fields, player-init messages,
map identifiers, coordinate units, movement messages, packet framing or login
semantics. It is not exposed as an HTTP route and does not make the original
APK compatible.

## Tests

Run:

```sh
python -m unittest discover -s tests -p 'test_sqlite_authorized_world_state_service.py' -v
```
