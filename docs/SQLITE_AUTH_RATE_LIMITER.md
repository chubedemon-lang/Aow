# Persistent synthetic authentication rate limiter

**Scope:** local SQLite account-authentication support only. This is not an
AOW login packet, a client-facing authentication endpoint, or evidence of APK
compatibility.

## Durable schema contract

`SqliteAuthRateLimiter` stores only a keyed HMAC-SHA256 digest of the supplied
principal. It does not persist usernames or passwords. The operator-supplied
HMAC secret must remain stable across restarts if existing failure buckets
should remain addressable.

Initialization is fail-closed:

- An already initialized table is validated without taking a write
  reservation on the main database.
- A missing table is created and validated inside one `BEGIN IMMEDIATE`
  transaction.
- Existing tables must have the exact four-column layout, a single primary
  key on `principal_digest`, the required non-negative and digest-shape
  constraints, and no triggers that could add hidden side effects.
- Required constraints are exercised against a private in-memory clone of the
  stored table DDL. Probe rows never touch the operator's database.
- An incompatible table/view/index/trigger is rejected; initialization does
  not silently adopt or repair it.

The limiter uses a durable fixed window and bounded lockout per keyed
principal. It is not a network-edge limiter: a future authorized adapter must
also apply source-aware throttling at a trusted transport boundary, use
transport security, and avoid trusting caller-supplied forwarding headers.

## Validation

Run:

```sh
python -m unittest discover -s tests -p 'test_sqlite_auth_rate_limiter.py' -v
```

The tests cover schema validation, no-write initialization for an existing
valid schema, transaction ownership, lockout boundaries, concurrent failures,
and the fact that only keyed digests are persisted.

A passing suite proves only the synthetic SQLite component. It does not
establish AOW credentials, session-restore semantics, handshake order, packet
framing, or unchanged-APK compatibility.
