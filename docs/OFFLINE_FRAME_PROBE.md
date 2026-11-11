# Synthetic offline frame probe

`server/offline_frame_probe.py` is a **generic, bounded length-prefix stream decoder** for unit tests and authorized offline research. It is **not** an AOW packet decoder and does not establish that AOW uses a length prefix, particular byte order, header width, encryption, or handshake.

Use it only after offline evidence independently supports a particular `FrameSpec(length_bytes, byteorder, includes_header, max_payload)`. Record sanitized source locators in the evidence ledger. Do not publish APK bytes, proprietary extracted code, endpoints, raw packet captures, or credentials.

Run `python -m unittest discover -s tests -p 'test_offline_frame_probe.py'` from repository root. Tests use fabricated byte streams and cover split/coalesced frames, both endian orders, header-inclusive lengths, malformed sizes, and truncation. No connection to the official service is made.

Before claiming APK compatibility: trace the IL2CPP transport and serialization call path from the authorized APK, confirm framing and login on an isolated local test server, and record end-to-end evidence for the same APK SHA-256.


## Resource bounds

`FrameSpec.max_chunk_bytes` caps each individual `feed()` call (default 4 MiB, hard maximum 16 MiB). A frame may be fragmented across multiple calls, so `max_payload` can exceed the per-call limit. An oversized feed poisons the decoder and clears pending bytes before copying the chunk into its internal buffer. This is a synthetic parser safety limit, not an AOW protocol limit.
