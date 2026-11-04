# Evidence-gated transport boundary

`server/transport.py` is an **offline interface only**. It does not open sockets, parse AOW frames, claim that the original APK connects, or contact official services. Default behavior raises `UnverifiedProtocolError`.

A future codec must be backed by an authorized offline APK analysis report with a SHA-256 source identifier, a specific observation, and a review reference. The evidence object is metadata, **not proof** that the codec matches the APK; the `verified` property currently means only that evidence metadata and both codec callbacks were supplied. Compatibility must be demonstrated separately through authorized, local end-to-end tests with the unchanged APK.

Before a real codec can be implemented, document: transport selection; message framing; byte order; handshake order; authentication ownership; request/response identifiers; encryption/compression if present; errors and reconnect semantics. Each fact needs a reproducible source reference and negative test. Keep original APKs, assets, tokens, endpoints with private paths, and raw traffic out of public commits.

Synthetic test fixtures in `tests/test_transport.py` exercise fail-closed behavior, input validation and codec boundaries. They are not evidence of an original wire format.
