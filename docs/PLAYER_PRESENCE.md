# Synthetic player presence registry

`server/player_presence.py` maintains an in-memory, single-process mapping of authenticated sessions to players and optional map membership. It rejects duplicate player ownership, unauthorized session operations, invalid map IDs, and map reentry without leaving first.

**Usage order:** create Session → authenticate → registry.bind → session.enter_world → registry.enter_map → registry.leave_map → session.leave_world → registry.release → session.close.

This is not persistent, distributed, thread-safe, network-facing, or connected to any AOW APK packet. Callers must serialize mutations and release presence **before** closing a Session (closure clears player_id). A crash or disconnect cleanup must use a higher-level coordinator to ensure both registry release and session closure. No client protocol, packet ID, endpoint, or login handshake is inferred here.

Run: `python -m unittest discover -s tests`.
