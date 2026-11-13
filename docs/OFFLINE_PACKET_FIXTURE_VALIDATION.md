# Offline packet fixture provenance gate

**Scope:** validate private, authorized byte fixtures locally. This document
does not describe or infer the AOW packet format.

## Required source binding

Call validate_packet_fixture with both the fixture record and
expected_source_sha256. The expected digest must be obtained independently
from the operator's trusted private inventory for the exact APK build or local
capture under examination. The record's self-declared source_sha256 must
match that value.

For a batch containing more than one source artifact, call
validate_fixture_batch with expected_source_sha256s: a finite collection of
independently obtained digests from the same trusted inventory. Every record
must match one of those digests before its payload is decoded. Do not build this
allowlist from untrusted fixture records in production code.

The validators also require:

- an explicit boolean verified: true;
- a lowercase SHA-256 digest for each payload;
- strict even-length hexadecimal payload text (the empty string is valid for
  a zero-byte payload);
- a payload digest matching the decoded bytes, including the standard SHA-256
  digest of an empty byte string;
- caller-selected per-fixture and aggregate size limits.

The single-fixture function returns immutable bytes only after its checks.
The batch function returns only count, aggregate byte size and payload digests;
it never returns or logs the payloads. A zero-byte fixture remains admissible
when earlier records have consumed the full aggregate byte budget; the batch
validator still checks its source binding, explicit verification flag and
payload digest. Any non-empty fixture is rejected once no aggregate budget
remains.

## Limits

A matching source digest binds a fixture record to the caller-selected artifact
identity; it does not prove that the artifact was authorized, that the bytes
were observed from the client, or that the bytes have a particular protocol
meaning. A payload hash proves integrity of the supplied hex, not packet
semantics. Accepting a zero-byte payload is a generic byte-fixture property;
it does not claim that any AOW message has an empty body.

Keep actual fixture records and bytes in a private local workspace. Do not add
APK files, native libraries, packet captures, endpoints, credentials or player
data to this public repository. Synthetic tests use invented bytes only.

Run:

~~~sh
python -m unittest discover -s tests -p 'test_offline_packet_fixture.py' -v
python -m unittest discover -s tests -p 'test_offline_fixture_batch.py' -v
python -m unittest discover -s tests -p 'test_offline_fixture_privacy_boundaries.py' -v
~~~
