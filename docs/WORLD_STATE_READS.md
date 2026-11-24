# Authorized synthetic world-state snapshots

**This is a local persistence/domain integration, not an AOW player-init or
map-join wire contract.**

SqliteAuthorizedWorldStateService reads the owned character row, durable
player snapshot and durable map-position snapshot inside one BEGIN IMMEDIATE
transaction.

The service also provides enter_and_get_snapshot,
move_and_get_snapshot, move_validated_and_get_snapshot and
leave_and_get_snapshot. Each operation:

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

The optional move_validated_and_get_snapshot path applies the existing
transport-independent MovementValidator before a new durable move. Its
max_speed is a synthetic coordinate-units-per-second policy supplied by the
server. elapsed_seconds must be measured by a trusted server-side monotonic
clock; it must never come from a client timestamp. A rejected move rolls back
without advancing the revision or writing a receipt. Exact idempotent retries
return the original receipt and current world snapshot without re-running the
movement policy. This is a reusable server-side guard, not an AOW speed, physics,
collision or movement-packet contract.

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


## Focused regression coverage

The Protocol Discovery workflow runs
`test_sqlite_authorized_world_state_service.py` in the dedicated
`authorized-world-state` job. The suite covers:

- one coherent character/player/map snapshot;
- enter, move and leave transitions with the returned snapshot from the same
  authorization transaction;
- idempotent replay semantics (original receipt versus current world view);
- rollback when a post-mutation snapshot read fails;
- foreign/unknown character indistinguishability and session expiry/revocation;
- revocation serialization with an in-flight movement snapshot;
- constructor schema and active-transaction preconditions.

All cases use temporary SQLite databases and synthetic values. They do not
exercise AOW packets, APK compatibility or any official endpoint.
