# Durable synthetic SQLite sessions

`server/sqlite_session_store.py` is a persistence primitive for future server-side integration. It is **not** an AOW APK login implementation and does not verify passwords, parse handshake packets, or establish wire compatibility.

## Behavior

- Issues 256-bit random URL-safe bearer tokens.
- Persists only the SHA-256 token digest, account id, creation time and expiry time.
- Uses epoch time so expiry survives process restarts; tests inject a deterministic clock.
- Uses `BEGIN IMMEDIATE` for issue, resolve/expiry cleanup, revocation and purge operations.
- Evaluates the clock after acquiring the write lock, so waiting for SQLite does not bypass expiry.
- Enforces expiry at the exact boundary (`now >= expires_at`).
- Revocation is idempotent: the first call returns true; later calls return false.
- Concurrent revocation against separate SQLite connections has one winner.
- Rejects an already-active caller transaction instead of committing work owned by the caller.

## Integration requirements

The caller must authenticate the account before calling `issue`; this method is trusted server code, not a public route. The caller must verify account/character ownership and authorize every state-changing request after `resolve`. Keep tokens out of logs and never accept client-selected account ids. Use a persistent SQLite database file and an epoch-based clock; do not use `time.monotonic` for persisted expiries.

The store intentionally has no foreign key to the mock `accounts` table, so it can be tested independently. Account existence and authentication remain the responsibility of a future verified auth layer. This module does not replace the existing process-local `SessionManager` or connect to the synthetic HTTP API.

Run the focused test and full suite:

```sh
python -m unittest discover -s tests -p 'test_sqlite_session_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK bytes, proprietary assets, credentials or packet captures belong in this public repository.
