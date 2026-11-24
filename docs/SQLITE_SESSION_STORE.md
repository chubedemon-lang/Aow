# Durable synthetic SQLite sessions

`server/sqlite_session_store.py` is a persistence primitive for future server-side integration. It is **not** an AOW APK login implementation and does not verify passwords, parse handshake packets, or establish wire compatibility.

## Behavior

- Issues 256-bit random URL-safe bearer tokens.
- Persists only the SHA-256 token digest, account id, creation time and expiry time.
- Token entry points accept only an exact built-in `str`; string subclasses are rejected before regular-expression matching, encoding, or dictionary/database lookup. This prevents custom `encode()` or `__hash__()` hooks from running while validating an opaque bearer token.
- Uses epoch time so expiry survives process restarts; tests inject a deterministic clock.
- The injected clock must return an exact built-in `int` or `float`; numeric subclasses are rejected before float conversion so custom `__float__` hooks cannot affect expiry validation.
- A supplied clock must be callable; non-callable values are rejected before the session table or indexes are created.
- Exceptions raised by the clock are normalized to a generic `ValueError("session clock failed")` without exposing the clock's private exception text. Public operations roll back their own transaction; transaction-scoped issuance leaves the caller's transaction open for the caller to roll back.
- Rejects finite clock values when adding the requested TTL cannot produce a strictly later, finite expiry timestamp; this avoids leaking a SQLite constraint error for unrepresentable epochs.
- Uses `BEGIN IMMEDIATE` for issue, resolve/expiry cleanup, revocation and purge operations.
- Evaluates the clock after acquiring the write lock, so waiting for SQLite does not bypass expiry.
- Enforces expiry at the exact boundary (`now >= expires_at`).
- Revocation is idempotent: the first call returns true; later calls return false.
- The rotate() API atomically replaces an active bearer token, preserves its account binding, and makes the old token unusable in the same BEGIN IMMEDIATE transaction. Concurrent attempts to rotate one token have exactly one winner.
- The rotate_in_transaction() API performs the same replacement inside a caller-owned transaction and uses a savepoint so a failed rotation rolls back only its own partial work; the caller retains ownership of the outer commit/rollback.
- `revoke_all_for_account(account_id)` removes every session for one account (logout all devices), returns the deleted row count, and is idempotent when repeated. It uses `BEGIN IMMEDIATE` so it serializes with protected `authorized_transaction()` work on other connections.
- Concurrent revocation against separate SQLite connections has one winner.
- Rejects an already-active caller transaction instead of committing work owned by the caller.
- The constructor accepts only an exact built-in `sqlite3.Connection`; connection subclasses are rejected before any overridden properties or methods can run.
- The constructor validates the existing `durable_sessions` table's exact column names, declared types, nullability, primary-key layout and defaults before accepting it. It also validates the named non-unique expiry index and its target column; an incompatible pre-existing table or index is rejected instead of being silently reused.
- Constructor validates an already-complete table/index read-only and does not take a write lock on the common path. If the table or expiry index is missing, it rechecks and creates the required DDL inside one `BEGIN IMMEDIATE` transaction, then performs the same persisted CHECK-constraint probes before commit. A malformed pre-existing table therefore cannot bypass constraint validation merely because its expiry index was missing. If validation or a conflicting pre-existing object fails, all DDL created by that attempt is rolled back, leaving the prior schema untouched.

## Persisted-row validation

Every token resolution validates the stored account ID and both timestamps
before authorizing a session. Account IDs must remain positive SQLite integers;
creation and expiry values must be finite, non-negative numeric values; expiry
must be later than creation and no later than the store's maximum supported TTL.
The resolver does not coerce fractional account IDs or malformed timestamp
values into apparently valid sessions.

A corrupt row fails closed as an invalid session and is left untouched for
operator diagnosis. Runtime resolution also rejects a creation timestamp later
than the current epoch clock. This deliberately fails closed if the wall clock
moves backwards: the session remains unusable until the clock catches up or an
operator repairs the row. `resolve_in_transaction()` preserves the caller's
transaction ownership when it rejects a corrupt or not-yet-valid row. The
read-only integrity audit checks row structure but does not compare creation
timestamps with the current clock. These are synthetic session-store safeguards,
not APK authentication rules.

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
requires each stored token digest to be a 32-byte BLOB. It returns the session,
active-session and expired-session counts and does not delete expired rows,
repair corruption, or expose token digests. Expired rows remain included until
the separate `purge_expired()` cleanup operation runs.

The audit requires an idle connection and always rolls back its read
transaction on success or failure. In WAL mode, concurrent commits from other
connections do not change the snapshot being audited; a later audit observes
those commits. This is persistence diagnostics for synthetic server sessions,
not APK authentication evidence.

The audit also rejects duplicate token digests in legacy tables that lack the
current primary-key constraint. Duplicate digests could make one bearer token
resolve ambiguously to more than one account; the audit reports corruption and
leaves all rows untouched.

## Caller-owned transaction rejection

Public operations that open and commit their own transaction (issue,
resolve, revoke, revoke_all_for_account, and purge_expired) reject a
connection that is already inside a caller-owned transaction. They raise
ValueError before issuing SQL, leaving the caller's transaction and pending
writes untouched. Use issue_in_transaction or resolve_in_transaction
when composing work inside a caller-owned transaction; use
authorized_transaction when the authorization check and protected mutation
must share one BEGIN IMMEDIATE boundary. Integrity audits also require an
idle connection and remain read-only.

## Atomic bearer-token rotation

After a trusted authentication or session-renewal decision, server code may
rotate an active token:

~~~python
replacement = store.rotate(current_token, ttl_seconds=900)
# Persist/deliver only the replacement token; the old token is now invalid.
~~~

rotate() starts BEGIN IMMEDIATE, validates the old row against one captured
clock value, inserts a fresh 256-bit token digest for the same account, deletes
the old digest, and commits both changes together. Two connections racing to
rotate the same token serialize; one receives a replacement and the other gets
an invalid-session error.

When composing rotation into a larger account transaction, use
rotate_in_transaction(). It requires an active caller transaction and wraps
the insert/delete pair in a savepoint. If validation or either SQL operation
fails, only the rotation's work is rolled back; unrelated caller writes remain
inside the caller-owned transaction. The caller must still commit or roll back
the outer transaction.

Rotation is a generic synthetic session-store capability. It does not define
an AOW reconnect, refresh, session-restore packet, or APK login behavior.


## Persisted CHECK-constraint enforcement

Construction rejects a connection when `PRAGMA ignore_check_constraints` is
enabled. It also replays the persisted `durable_sessions` CREATE TABLE
statement in a separate in-memory SQLite database and verifies that the
required token-digest type/length, positive account ID, and expiry-order
constraints reject representative invalid rows. The probe never inserts into
the application database. The read-only integrity audit rechecks the
connection-level pragma so a caller cannot silently disable CHECK enforcement
after constructing the store and still receive a clean audit result.

This is a synthetic persistence invariant. It does not validate an AOW login
message, session-restore packet, or original-client compatibility.
