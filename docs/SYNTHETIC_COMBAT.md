# Synthetic combat domain

`server/combat.py` provides an immutable, deterministic, turn-based test domain.
It validates bounded integer stats, actor turns, minimum damage, defeat and
finished-battle rejection. Each attack returns a new state and an event, making
unit tests reproducible and avoiding implicit global state.

**Not APK-compatible.** Fighter statistics, turn order and damage calculation
are invented test rules, not recovered AOW mechanics. This module has no
network routes and does not authorize a client to choose another actor.
Before integration, verify combat packets, authoritative session-to-character
ownership, map/encounter eligibility, real skill and damage rules, replay
protection and persistence from permitted evidence.
