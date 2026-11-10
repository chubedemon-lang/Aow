# Synthetic world position tracker

`server/world_position.py` composes the in-memory presence registry and movement validator. It requires an authenticated in-world session bound to a map and **server-owned monotonic timestamps**. Duplicate spawn, stale timestamps, speed violations, session spoofing, and movement across map transitions are rejected.

The tracker uses an in-process reentrant lock to serialize spawn, move, despawn, and read operations, preventing concurrent movement calls from overwriting a newer accepted timestamp. Timestamp conversion rejects booleans, non-finite values, and integers outside the finite float range. This lock is process-local only: it does not coordinate multiple server processes or make a concurrent session/map lifecycle transition atomic. The caller must serialize map leave/change and session release with tracker operations.

Call `despawn` before map transitions or session release; then `spawn` on the next map. No client-supplied timestamps should be trusted.

This remains non-persistent synthetic domain logic. Map bounds, collisions, transport framing, handshake, actual AOW movement rules and APK compatibility remain **unverified**. Do not expose it as a production wire handler before offline protocol evidence and end-to-end client tests.
