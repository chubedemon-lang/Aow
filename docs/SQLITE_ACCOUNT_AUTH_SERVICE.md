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

The expensive KDF runs before acquiring SQLite's writer lock. After successful
verification, the service starts `BEGIN IMMEDIATE`, re-reads the credential
and rejects the request if it changed, then calls
`SqliteSessionStore.issue_in_transaction`. Credential recheck and durable
session insertion commit together.

The returned opaque token is shown once; only its SHA-256 digest is stored in
`durable_sessions`. Do not log, serialize, or commit the token.

## Hard limits

- Enrollment is a trusted local setup operation, not a public registration API.
- No HTTP route is added; no rate limiter or transport security is provided.
  Any future adapter must add per-account and per-source rate limiting,
  monitoring, TLS where applicable, and abuse controls before exposure.
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
