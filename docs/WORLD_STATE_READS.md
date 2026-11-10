# Authorized synthetic world-state snapshots

**This is a local persistence/domain integration, not an AOW player-init or
map-join wire contract.**

`SqliteAuthorizedWorldStateService.get_snapshot(token, character_id)` reads
the owned character row, durable player snapshot and durable map-position
snapshot inside one `BEGIN IMMEDIATE` transaction.

The operation:
- validates the durable session and character ownership first;
- reads the character, player and map records from the same SQLite connection;
- serializes with session revocation and other protected writes;
- does not create missing player/map snapshots or repair incomplete state;
- rolls back the transaction on authorization or missing-state errors.

A missing player or map snapshot fails closed with the corresponding store
error. The service intentionally does not invent defaults at read time.

## Scope

All values remain synthetic. This read model does not define AOW character
fields, player-init messages, map identifiers, coordinate units, movement
messages, packet framing or login semantics. It is not exposed as an HTTP route
and does not make the original APK compatible.

## Tests

Run:

```sh
python -m unittest discover -s tests -p 'test_sqlite_authorized_world_state_service.py' -v
```
