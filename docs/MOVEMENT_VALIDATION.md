# Synthetic movement validation

`server/movement_validation.py` provides a transport-independent movement sanity check for future map simulation. `max_speed` is a synthetic configurable domain rule, **not** an AOW APK-derived speed or movement packet definition. Validation rejects non-finite positions, non-positive/invalid elapsed time, and displacements exceeding `max_speed * elapsed_seconds` (with small floating-point tolerance).

No server listener, APK framing, handshake, login, map geometry, authoritative clock, anti-cheat, or end-to-end client test is provided here. Do not wire this module into a production listener before a verified protocol adapter and authoritative server tick model exist.

Run: `python -m unittest discover -s tests`.
