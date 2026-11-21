# Synthetic SQLite account authentication

**This is not the AOW APK login protocol.** It is a local domain primitive for
testing account credential verification and durable session issuance after the
real client-facing protocol and credential semantics have been independently
established.

## Credential storage

`server/sqlite_account_auth_service.py` stores one credential per existing
`accounts` row:

- PBKDF2-HMAC-SHA256 with 600,000 iterations by default.
- A cryptographically random 16-byte salt per account.
- A 32-byte derived digest; plaintext passwords are never persisted.
- The iteration count and algorithm identifier are stored with each digest.
- Password enrollment is insert-only. Password reset requires a separate
  trusted administrative flow and is deliberately not implemented here.

The service accepts passwords containing 12 to 1,024 Unicode characters and
at most 4,096 UTF-8 bytes. Test cases use 100,000 iterations to keep CI runtime
bounded; that test setting is not the production default.

## Authentication and session issuance

`authenticate_and_issue_session` returns the same generic
`AccountAuthError("invalid credentials")` for unknown usernames, missing
credentials, malformed credential rows and wrong passwords. Unknown-account
paths perform a dummy PBKDF2 derivation to reduce obvious timing differences.

The expensive KDF runs before acquiring SQLite's writer lock. Username lookup
is bounded to two rows and fails closed unless exactly one account matches;
this protects legacy account tables that do not enforce `UNIQUE(username)`
from arbitrary `fetchone()` selection. After successful verification, the
service starts `BEGIN IMMEDIATE`, re-reads the credential and again requires
one unambiguous username match before calling
`SqliteSessionStore.issue_in_transaction`. Credential recheck and durable
session insertion commit together.

The public enrollment and authentication methods own their SQLite write
transactions. They reject an already-active caller transaction before running
password KDF work, invoking the optional rate limiter, or performing account
lookups. Do not call these public methods inside a larger caller-owned
transaction; use explicitly transaction-scoped primitives where composition
is required.

The returned opaque token is shown once; only its SHA-256 digest is stored in
`durable_sessions`. Do not log, serialize, or commit the token.

The account-auth service and its optional rate limiter also require an exact built-in `sqlite3.Connection`; connection subclasses are rejected before any overridable connection property or method is accessed. An injected limiter must be an exact `SqliteAuthRateLimiter` instance bound to that same connection. This keeps the authentication transaction boundary consistent with the durable session store.

Username and password inputs accept exact built-in `str` values only. String
subclasses are rejected before validation calls such as `len()`, `strip()`,
or `encode()` can dispatch caller-defined hooks. The rate limiter applies the
same rule to principal identifiers; non-exact strings are grouped into its
bounded invalid-principal bucket rather than receiving a separate bypassable
bucket.

## Optional authentication throttling

`server/sqlite_auth_rate_limiter.py` provides a persistent fixed-window failure
counter that can be injected into `SqliteAccountAuthService` through the
`rate_limiter` argument. It stores only a 32-byte HMAC-SHA256 digest of the
username bucket, an attempt count and timestamps; it never stores the username
or the HMAC secret. The secret must contain at least 32 bytes and should be
loaded from an operator secret manager. Keep it stable across restarts to
preserve active buckets; rotating it intentionally makes prior buckets
unreadable.

The limiter records failed credentials, clears the bucket after successful
authentication in the same transaction as durable session issuance, and
serializes counter updates with `BEGIN IMMEDIATE`. Its fixed-window and lockout
settings and the maximum number of stored principal buckets are bounded and
injectable for deterministic tests. Expired windows and completed lockouts are
pruned before a new bucket is inserted. At capacity, new principal buckets fail
closed while existing buckets remain usable; this prevents unbounded database
growth from arbitrary unknown usernames.

The limiter samples its clock only after SQLite grants the write
reservation. `check_allowed` owns a `BEGIN IMMEDIATE` transaction; the
caller-owned `record_failure_in_transaction` primitive first performs a
zero-row update to upgrade a deferred transaction to a writer reservation.
A request waiting behind another writer therefore evaluates lockout expiry
against the current clock rather than a stale timestamp captured before the
wait. If SQLite cannot safely upgrade an existing deferred read transaction,
the database error is propagated and the caller remains responsible for
rolling back its transaction. Clock provider exceptions are normalized to a
generic `ValueError` so private operator exception text is not propagated
through the authentication boundary.

The limiter is per-username only. It does not replace per-source/network rate
limits, trusted reverse-proxy handling, monitoring, TLS where applicable, or
other abuse controls. The service still has no HTTP route and remains a local
synthetic foundation.

## Hard limits

- Enrollment is a trusted local setup operation, not a public registration API.
- Any future adapter must require a configured limiter, add per-source rate
  limiting, monitoring, TLS where applicable, and abuse controls before
  exposure. Do not treat the optional constructor argument as a production
  deployment policy.
- This module does not infer the APK's password encoding, hashing, challenge,
  token format, message IDs, field order, handshake, or login sequence.
- Do not connect it to the APK adapter until authorized offline evidence and a
  redacted, reproducible test fixture establish the actual login contract.
- No APK, proprietary assets, credentials, packet captures, or extracted
  endpoint values belong in this public repository.

## Focused tests

```sh
python -m unittest discover -s tests -p 'test_sqlite_account_auth_service.py' -v
python -m unittest discover -s tests -p 'test_sqlite_session_store.py' -v
```
