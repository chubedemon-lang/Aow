# Offline packet fixture provenance gate

**Scope:** validate a private, authorized byte fixture locally. This document
does not describe or infer the AOW packet format.

## Required source binding

Call validate_packet_fixture with both the fixture record and
expected_source_sha256. The expected digest must be obtained independently
from the operator's trusted private inventory for the exact APK build or local
capture under examination. The record's self-declared source_sha256 must
match that value.

The validator also requires:

- an explicit boolean verified: true;
- a lowercase SHA-256 digest for the payload;
- strict even-length hexadecimal payload text;
- a payload digest matching the decoded bytes;
- a caller-selected maximum size between 1 byte and 1 MiB.

The function returns immutable bytes only after these checks. It does not log
or persist payloads.

## Limits

A matching source digest binds a fixture record to the caller-selected artifact
identity; it does not prove that the artifact was authorized, that the bytes
were observed from the client, or that the bytes have a particular protocol
meaning. The caller must establish authorization and provenance independently.
A payload hash proves integrity of the supplied hex, not packet semantics.

Keep actual fixture records and bytes in a private local workspace. Do not add
APK files, native libraries, packet captures, endpoints, credentials or player
data to this public repository. Synthetic tests use invented bytes only.

Run:

~~~sh
python -m unittest discover -s tests -p 'test_offline_packet_fixture.py' -v
~~~
