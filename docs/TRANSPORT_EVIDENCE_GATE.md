# Evidence-gated transport boundary

`server/transport.py` is an **offline interface only**. It does not open sockets, parse AOW frames, claim that the original APK connects, or contact official services. Default behavior raises `UnverifiedProtocolError`.

A future codec must be backed by an authorized offline APK analysis report with a SHA-256 source identifier, a specific observation, and a review reference. The evidence object is metadata, **not proof** that the codec matches the APK; the `configured` property currently means only that evidence metadata and both codec callbacks were supplied. Compatibility must be demonstrated separately through authorized, local end-to-end tests with the unchanged APK.

Review references are deliberately restricted to short, sanitized local locators such as `issue:2` or `docs/PROTOCOL.md#framing`. The validators reject URI schemes, DNS hostnames, IPv4/IPv6 literals, localhost, host:port values, secret-like identifiers and unbounded values while preserving repository-local paths and issue references. Do not place endpoint strings, credentials, raw packet bytes or private capture paths in evidence metadata.

Before a real codec can be implemented, document: transport selection; message framing; primitive serialization; handshake order; authentication ownership; request/response identifiers; encryption/compression if present; errors and reconnect semantics. Each fact needs a reproducible source reference and negative test. Keep original APKs, assets, tokens, endpoints with private paths, and raw traffic out of public commits.

Synthetic test fixtures in `tests/test_transport.py` exercise fail-closed behavior, input validation and codec boundaries. They are not evidence of an original wire format.

The evidence readiness sequence is transport → framing → serialization → handshake → login → session → player initialization → map join → movement → inventory → shop → combat → quest. Each stage requires its own verified evidence record; a later record cannot bypass a missing prerequisite. These gates track evidence coverage only and do not claim APK compatibility.

**Fingerprint isolation:** `evaluate_evidence()` requires all records in one evaluation to refer to a single artifact SHA-256. If multiple fingerprints are present, the caller must pass `artifact_sha256` explicitly; the gate then filters to that artifact before evaluating prerequisites. Evidence from different APK builds must never be combined to make a stage appear ready. This is a bookkeeping safeguard, not a compatibility test.

**Reproducibility requirement:** records in `server.protocol_evidence_registry.Evidence` marked `verified=True` must include both a sanitized repository-local `test_reference` and a reproducible local `reproduction` command. Verified records must identify an offline APK-analysis or authorized-local-test method; a `synthetic_test` method alone cannot unlock a protocol stage. The command/reference are provenance metadata, not proof by themselves, and the registry still does not establish wire compatibility.

Primitive serializer findings from the authorized offline APK pass are not by themselves a complete message schema or proof that a specific serializer is used by the active transport. The serialization gate is deliberately separate from framing and handshake.

## Public evidence ledger locator policy

`server/evidence_ledger.py` stores public provenance metadata only. It accepts short local references such as `issue:2`, `docs/PROTOCOL.md#framing`, `metadata/type:123`, and test paths. It rejects URI schemes, hostnames, IP literals, localhost and host:port locators so private endpoints are not accidentally published. This is a conservative metadata filter, not a general-purpose data-loss-prevention system.


**Registry summary fingerprint isolation:** the evidence registry refuses to aggregate observations when it contains multiple APK SHA-256 values unless the caller selects one explicitly. The returned topic counts then include only records for that selected artifact. This mirrors the ordered readiness gate and prevents evidence from different builds being combined in a summary. It is a bookkeeping safeguard, not a compatibility test.
