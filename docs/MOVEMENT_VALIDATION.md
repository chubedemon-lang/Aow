# Synthetic movement validation

`server/movement_validation.py` provides a transport-independent movement sanity check for future map simulation. `max_speed` is a synthetic configurable domain rule, **not** an AOW APK-derived speed or movement packet definition.

Validation rejects:

- non-finite or non-numeric coordinates (including integers that cannot be represented in finite float space);
- boolean, non-finite, non-positive or unrepresentable elapsed time;
- invalid speed and tolerance configuration (speed must be positive; tolerance must be non-negative);
- coordinate subtraction, distance, or allowed-distance arithmetic that overflows to a non-finite result;
- displacements exceeding `max_speed * elapsed_seconds + epsilon`.

An overflowed movement allowance is rejected rather than interpreted as an unlimited speed budget. The validator uses a configurable floating-point tolerance only; it does not establish a game tick rate or coordinate unit.

No server listener, APK framing, handshake, login, map geometry, authoritative clock, anti-cheat, or end-to-end client test is provided here. Do not wire this module into a production listener before a verified protocol adapter and authoritative server tick model exist.

Run: `python -m unittest tests.test_movement_validation -v`.
