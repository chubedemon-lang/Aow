# Durable synthetic session integrity audit

**Scope:** local synthetic server persistence only. This is not the AOW APK
login protocol, a production authentication endpoint, or evidence of client
compatibility.

## Audit behavior

`SqliteSessionStore.verify_integrity()` requires an idle SQLite connection
and opens one consistent read snapshot. It runs SQLite `quick_check`, then
streams every durable session row through the same strict account and expiry
validation used by session resolution.

The report contains:

- `session_count`: all structurally valid stored rows;
- `active_session_count`: rows not expired at the single captured clock value;
- `expired_session_count`: structurally valid rows already expired at that value.

The audit also rejects non-BLOB or non-32-byte token digests, invalid account
identifiers, non-finite or malformed timestamps, expiry values outside the
maximum permitted TTL, and sessions whose creation time is in the future
relative to the captured clock.

## Read-only guarantee

The audit does not delete expired sessions, revoke tokens, repair rows, or
return token digests. It rolls back its read transaction in a `finally`
block, including when validation fails. Expired-row cleanup remains the
separate explicit `purge_expired()` operation.

A successful audit is a database-integrity result only. It does not validate
the account's current existence, credential status, AOW session semantics,
packet framing, handshake, or APK compatibility.

## Synthetic test coverage

The session-store regression suite covers:

- active/expired counts at an exact expiry boundary;
- no mutation of expired rows during the audit;
- rejection of malformed token-digest storage;
- rejection of corrupt account and expiry values;
- rejection of future-dated sessions without repairing the row;
- stable read-snapshot behavior while another connection issues a session;
- refusal to take over a caller-owned transaction.
