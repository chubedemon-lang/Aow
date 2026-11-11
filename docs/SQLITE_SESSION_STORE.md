# Durable synthetic SQLite sessions

`server/sqlite_session_store.py` is a persistence primitive for future server-side integration. It is **not** an AOW APK login implementation and does not verify passwords, parse handshake packets, or establish wire compatibility.

## Behavior

- Issues 256-bit random URL-safe bearer tokens.
- Persists only the SHA-256 token digest, account id, creation time and expiry time.
- Uses epoch time so expiry survives process restarts; tests inject a deterministic clock.
- Rejects finite clock values when adding the requested TTL cannot produce a strictly later, finite expiry timestamp; this avoids leaking a SQLite constraint error for unrepresentable epochs.
- Uses `BEGIN IMMEDIATE` for issue, resolve/expiry cleanup, revocation and purge operations.
- Evaluates the clock after acquiring the write lock, so waiting for SQLite does not bypass expiry.
- Enforces expiry at the exact boundary (`now >= expires_at`).
- Revocation is idempotent: the first call returns true; later calls return false.
- Concurrent revocation against separate SQLite connections has one winner.
- Rejects an already-active caller transaction instead of committing work owned by the caller.

## Expired-session cleanup

`purge_expired()` preserves the original behavior and removes every expired row in one transaction.

For larger stores, callers can bound the write-lock duration by using `purge_expired(batch_size=500)`. A batch size must be an integer from 1 through 10,000 (booleans are rejected). The store removes at most that many oldest expired rows, ordered by expiry and token digest, and returns the number deleted. Repeat the call until it returns zero. Active sessions are never selected. The batch size is a cleanup control only; expiry is still enforced on every resolve operation.

## Integration requirements

The caller must authenticate the account before calling `issue`; this method is trusted server code, not a public route. The caller must verify account/character ownership and authorize every state-changing request after `resolve`. Keep tokens out of logs and never accept client-selected account ids. Use a persistent SQLite database file and an epoch-based clock; do not use `time.monotonic` for persisted expiries.

The store intentionally has no foreign key to the mock `accounts` table, so it can be tested independently. Account existence and authentication remain the responsibility of a future verified auth layer. This module does not replace the existing process-local `SessionManager` or connect to the synthetic HTTP API.

Run the focused test and full suite:

```sh
python -m unittest discover -s tests -p 'test_sqlite_session_store.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

No APK bytes, proprietary assets, credentials or packet captures belong in this public repository.
