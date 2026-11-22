# Protocol evidence object boundaries

The protocol evidence registry and readiness gates are bookkeeping controls for
authorized offline analysis. They are not packet decoders and do not establish
APK compatibility.

## Accepted object shapes

- Registry records must be exact instances of `Evidence`; subclasses are
  rejected before any record fields are read.
- Gate input must be an exact built-in `list` or `tuple`, containing only
  exact `Evidence` instances, with at most 4,096 records per evaluation.
- The approved-digest allowlist must be an exact built-in `list`, `tuple`, or
  `frozenset`, with at most 4,096 entries.
- Artifact fingerprints must be exact built-in lowercase SHA-256 strings.
- Evidence digest input must be exact immutable `bytes`.

These constraints prevent caller-defined subclasses from running custom
attribute, iteration, conversion, or equality hooks while evidence is being
accepted or evaluated. The collection caps also bound the work and temporary
memory used to validate records, build the fingerprint set, and materialize
the approved-digest allowlist. They also keep the registry and ordered gates
on the same narrow input contract.

## Static verification versus protocol readiness

The registry's `verified` flag means that the recorded observation was
reproduced by its declared method. It does **not** mean that the observation
is sufficient to unlock a client-facing protocol stage.

The ordered readiness gates count a record only when all of the following are
true:

1. The record belongs to the explicitly selected APK fingerprint (or the
   registry contains only one fingerprint).
2. Its `verified` flag is true.
3. Its method is exactly `authorized_local_test`.
4. The SHA-256 digest of the exact record is present in the caller-supplied
   `approved_evidence_digests` allowlist.
5. Every preceding stage has an eligible record for that same fingerprint.

The allowlist defaults to empty and the repository ships no approved protocol
record digests. A verification flag, method string, local test path, or
synthetic fixture cannot unlock a stage on its own. The digest is computed from
canonical JSON containing the artifact hash, topic, observation, method,
verification flag, reproduction command, and local test reference. It binds
approval to those exact fields, but it is **not a signature** and does not prove
fixture authenticity. Populate the allowlist only after independent human
provenance review of a redacted fixture or local runtime trace from the exact
unchanged APK build.

Static methods such as `apk_zip_inventory`, `jadx_offline`, and
`il2cpp_offline` remain useful and may verify static facts: APK integrity,
metadata associations, native callsites, or primitive serializer behavior.
They cannot by themselves establish active transport, complete outer framing,
compression/encryption activation, handshake order, LoginRequest field order,
session behavior, or later gameplay exchanges. Even a static fact with a
reproducible unit test remains static evidence and does not satisfy a stage
gate.

For `authorized_local_test`, the referenced local test/fixture must be a
redacted reproduction derived from an authorized run of the exact unchanged
APK build, or a local runtime trace from that build. A fabricated packet,
synthetic-only unit test, method name, metadata string, or guessed schema is
not sufficient. The registry validates the declared provenance shape; human
review must still verify that the referenced fixture really has that origin.
Never commit private packet bytes, credentials, endpoint values, or player data.

## Concurrent registry snapshots

`EvidenceRegistry.add()` and `EvidenceRegistry.summary()` serialize access to the
in-memory record list with one process-local lock. Each summary captures an
immutable tuple while holding that lock, then uses only that tuple for both
artifact-fingerprint selection and per-topic aggregation. A record added after
the snapshot is therefore visible to the next summary, not midway through the
current one. This prevents a concurrent update from bypassing the mixed-build
guard. The lock provides process-local consistency only; it is not a durable
store, authorization proof, or fixture-authenticity check.

## Validation

```sh
python -m unittest discover -s tests -p 'test_protocol_evidence_registry.py' -v
python -m unittest discover -s tests -p 'test_protocol_evidence_gates.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
```

Free-text metadata is screened in its literal form and after up to three
percent-decoding rounds. If valid percent escapes remain after that bound, the
validator rejects the value conservatively. This prevents encoded URLs,
addresses, credentials, absolute paths, traversal segments, and raw-byte
markers from bypassing the public metadata boundary. This remains a bounded
guardrail rather than a general-purpose data-loss-prevention scanner.

Synthetic hostile-subclass tests validate only the Python input boundary.
They do not add native APK observations, packet fixtures, wire semantics,
handshake/login evidence, or an interoperability claim. Keep the original APK,
native assets, packet bytes, captures, endpoint values, and credentials out of
the public repository.

## Public metadata manifest input boundary

The metadata-only manifest path is equally strict: JSON ingestion accepts only
exact built-in `bytes`; decoded manifests must be exact built-in `list`
objects; records must be exact built-in `dict` objects; dictionary keys and
free-text values must be exact built-in `str` objects. These checks happen
before length, decoding, iteration, indexing, hashing, or string methods can
dispatch to caller-defined subclass hooks.

This is input-boundary hardening for the evidence bookkeeping tools only. It
does not add APK observations, packet fixtures, protocol semantics, or an
interoperability claim.
