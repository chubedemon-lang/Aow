# Evidence-gated transport boundary

`server/transport.py` is an **offline interface only**. It does not open sockets, parse AOW frames, claim that the original APK connects, or contact official services. Default behavior raises `UnverifiedProtocolError`.

A future codec must be backed by an authorized offline APK analysis report with a SHA-256 source identifier, a specific observation, and a review reference. The evidence object is metadata, **not proof** that the codec matches the APK; the `configured` property currently means only that evidence metadata and both codec callbacks were supplied. Compatibility must be demonstrated separately through authorized, local end-to-end tests with the unchanged APK.

Before a real codec can be implemented, document: transport selection; message framing; primitive serialization; handshake order; authentication ownership; request/response identifiers; encryption/compression if present; errors and reconnect semantics. Each fact needs a reproducible source reference and negative test. Keep original APKs, assets, tokens, endpoints with private paths, and raw traffic out of public commits.

Synthetic test fixtures in `tests/test_transport.py` exercise fail-closed behavior, input validation and codec boundaries. They are not evidence of an original wire format.

The evidence readiness sequence is transport → framing → serialization → handshake → login → session → player initialization → map join → movement → inventory → shop → combat → quest. Each stage requires its own verified evidence record; a later record cannot bypass a missing prerequisite. These gates track evidence coverage only and do not claim APK compatibility.

Primitive serializer findings from the authorized offline APK pass are not by themselves a complete message schema or proof that a specific serializer is used by the active transport. The serialization gate is deliberately separate from framing and handshake.
