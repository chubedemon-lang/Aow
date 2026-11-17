# SQLite authorization trust boundary

The synthetic account, character, player, map, inventory, shop and combat
facades share one durable-session authorization boundary. The boundary relies
on concrete built-in SQLite and repository-owned authorization objects; it is
not an extension point for connection, session-store or authorizer subclasses.

## Accepted runtime objects

- SQLite connections must have exact type `sqlite3.Connection`. A subclass can
  override `execute`, `in_transaction`, `commit` or other methods and run
  arbitrary Python code before a downstream store rejects it.
- `SqliteCharacterAuthorizer` must be the repository's exact concrete class
  when entering `authorized_character_transaction`.
- Its session store must have exact type `SqliteSessionStore` and must use the
  same connection object.
- These checks run before reading overridable properties or invoking methods.

The session store, inventory store, map-position store, shop store and
reward ledger require an exact built-in SQLite connection. The authorized
facades and schema preflight helpers apply the same rule so an unsupported
subclass is rejected before any schema query, transaction-state read, PRAGMA
or table creation.

## Scope and compatibility

This hardening affects only local synthetic SQLite services. It does not
identify AOW account/session formats, implement a login packet, or establish
APK compatibility. Existing callers should pass a normal connection returned
by `sqlite3.connect` and repository-created `SqliteSessionStore` /
`SqliteCharacterAuthorizer` instances.

## Validation

Run:

```sh
python -m unittest discover -s tests -p 'test_sqlite_connection_boundaries.py' -v
```

The regression suite uses hostile synthetic subclasses to prove that rejected
objects cannot execute overridden accessors or methods. No APK, native asset,
packet fixture, endpoint, credential or player data is needed.
