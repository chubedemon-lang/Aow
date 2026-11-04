# Synthetic combat replay (server-only)

The bounded replay helper in `server/combat_replay.py` deterministically applies
actor turns to the immutable local `Battle` model. It returns the final snapshot
and a tuple of synthetic events. Optional expected events detect divergence.

This is **not** the original AOW combat protocol, packet framing, damage
formula, or gameplay specification. It does not connect to the APK or any
external endpoint. It is useful for testing server-side state transitions
while offline APK evidence remains unavailable.

Run `python -m unittest discover -s tests` from the repository root.

Limits: traces must be lists or tuples with at most 10,000 actions; actor IDs
must be bounded positive integers; invalid turns and post-victory actions fail.
This is a deterministic replay helper, not an authenticated or persistent
battle service.
