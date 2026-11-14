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
- `revoke_all_for_account(account_id)` removes every session for one account (logout all devices), returns the deleted row count, and is idempotent when repeated. It uses `BEGIN IMMEDIATE` so it serializes with protected `authorized_transaction()` work on other connections.
- Concurrent revocation against separate SQLite connections has one winner.
- Rejects an already-active caller transaction instead of committing work owned by the caller.

## Persisted-row validation

Every token resolution validates the stored account ID and both timestamps
before authorizing a session. Account IDs must remain positive SQLite integers;
creation and expiry values must be finite, non-negative numeric values; expiry
must be later than creation and no later than the store's maximum supported TTL.
The resolver does not coerce fractional account IDs or malformed timestamp
values into apparently valid sessions.

A corrupt row fails closed as an invalid session and is left untouched for
operator diagnosis. `resolve_in_transaction()` preserves the caller's
transaction ownership when it rejects a corrupt row. This protects the synthetic
session store from corrupted or manually altered SQLite values; it is not an
APK authentication rule.

## Authorized state transactions

Use `authorized_transaction(token)` when a protected read/write must be atomic
with session authorization:

```python
with store.authorized_transaction(token) as account_id:
    # Read and mutate account-owned rows using store.db here.
    # Do not commit or roll back inside this block.
    ...
```

The helper starts `BEGIN IMMEDIATE`, resolves the token after acquiring the
SQLite write reservation, yields the account id, then commits on success or
rolls back on any exception. A concurrent revocation on another connection
therefore waits until the protected operation commits; a revocation that wins
first causes the later authorization to fail. The connection must not already
own a transaction. This is a synthetic SQLite integration helper, not an AOW
handshake or login contract.

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

## Read-only integrity audit

`verify_integrity()` pins one SQLite read snapshot, runs
`PRAGMA quick_check`, then streams all durable-session rows through
the same strict account/expiry validation used by token resolution. It also
requires each stored token digest to be a 32-byte BLOB. It returns
`{"session_count": N}` and does not delete expired rows, repair
corruption, or expose token digests. Expired rows remain included until the
separate `purge_expired()` cleanup operation runs.

The audit requires an idle connection and always rolls back its read
transaction on success or failure. In WAL mode, concurrent commits from other
connections do not change the snapshot being audited; a later audit observes
those commits. This is persistence diagnostics for synthetic server sessions,
not APK authentication evidence.

The audit also rejects duplicate token digests in legacy tables that lack the
current primary-key constraint. Duplicate digests could make one bearer token
resolve ambiguously to more than one account; the audit reports corruption and
leaves all rows untouched.
