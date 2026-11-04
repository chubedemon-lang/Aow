# Synthetic world position tracker

`server/world_position.py` composes the in-memory presence registry and movement validator. It requires an authenticated in-world session bound to a map and **server-owned monotonic timestamps**. Duplicate spawn, stale timestamps, speed violations, session spoofing, and movement across map transitions are rejected. Call `despawn` before map transitions or session release; then `spawn` on the next map. No client-supplied timestamps should be trusted.

This is single-process, non-thread-safe, non-persistent domain logic. Map bounds, collisions, transport framing, handshake, actual AOW movement rules and APK compatibility remain **unverified**. Do not expose it as a production wire handler before offline protocol evidence and end-to-end client tests.
