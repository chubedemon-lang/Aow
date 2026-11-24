# Synthetic session lifecycle

This module provides a transport-agnostic lifecycle for future server integration:

`connected -> authenticated -> in_world -> authenticated` and terminal `closed`.

It does **not** authenticate AOW APK users, parse packets, implement handshake, or claim compatibility. The future transport adapter must only invoke authentication after verified protocol and credential validation. Session identifiers are local opaque strings, not APK-derived values.

The synthetic lifecycle accepts exact built-in `str` identifiers only. The movement model accepts exact `Position` instances only; caller-defined subclasses are rejected before custom length, iteration, or coordinate-access hooks can run. These are local Python trust-boundary rules, not client identifier or coordinate-format claims.

Tests cover forbidden transitions, terminal closure, reentry, invalid identifiers, hostile string subclasses, movement bounds, and hostile position subclasses.

Run: `python -m unittest discover -s tests`.
