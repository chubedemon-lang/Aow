# Synthetic session lifecycle

This module provides a transport-agnostic lifecycle for future server integration:

`connected -> authenticated -> in_world -> authenticated` and terminal `closed`.

It does **not** authenticate AOW APK users, parse packets, implement handshake, or claim compatibility. The future transport adapter must only invoke authentication after verified protocol and credential validation. Session identifiers are local opaque strings, not APK-derived values. Tests cover forbidden transitions, terminal closure, reentry, and invalid identifiers.

Run: `python -m unittest discover -s tests`.
