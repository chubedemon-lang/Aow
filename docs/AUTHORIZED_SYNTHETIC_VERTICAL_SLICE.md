# Authorized synthetic domain vertical slice

This test composes the existing local SQLite domain services with one durable
session database:

1. Synthetic account credential verification and session issuance.
2. Character creation with initial player and unplaced map snapshots.
3. Session-authorized map entry and movement.
4. Session-authorized inventory creation and mutation.
5. A trusted synthetic quest-award call that grants one inventory item with an
   idempotent receipt.
6. Cross-service ownership checks and session revocation.

The integration test is intentionally synthetic. Map ID 7, item IDs,
character values, quest ID 7, and all test credentials are fabricated. The
test does not define AOW account credentials, packet fields, character
initialization, map IDs, movement rules, inventory schema, quest semantics, or
wire messages.

The test verifies that independently constructed services sharing one SQLite
database can resolve the same durable session token, enforce character
ownership, serialize revocation with protected operations, and preserve
idempotent quest-award behavior. It is a domain integration test only; it does
not open a socket or connect the unchanged APK.

The real AOW adapter remains disabled until an authorized, provenance-reviewed
client-side byte fixture or local runtime trace establishes the complete
transport/framing/handshake/login contract. No APK, native library, packet
capture, credential, or proprietary asset belongs in this repository.
