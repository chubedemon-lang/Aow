"""Validate a batch of private offline fixtures without storing payload bytes.

No AOW protocol claims are made. Callers must supply independently trusted
source digests for every APK build or capture represented in the batch.
"""
import hashlib
import re

from server.offline_packet_fixture import FixtureValidationError, validate_packet_fixture

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def validate_fixture_batch(
    records, *, expected_source_sha256s, max_records=128, max_total_bytes=1048576
):
    """Return summary digests only; reject untrusted sources and over-budget input.

    expected_source_sha256s is a finite collection copied from the caller's
    trusted private artifact inventory. Each fixture's self-declared source
    digest must belong to that collection before its payload is decoded.

    Payloads are never returned, logged, written, or included in exceptions.
    """
    if type(max_records) is not int or not 1 <= max_records <= 1024:
        raise FixtureValidationError("invalid max_records")
    if type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 16777216:
        raise FixtureValidationError("invalid max_total_bytes")
    if type(records) not in (list, tuple) or not 1 <= len(records) <= max_records:
        raise FixtureValidationError("invalid fixture count")
    if (type(expected_source_sha256s) not in (set, frozenset, list, tuple)
            or not 1 <= len(expected_source_sha256s) <= 1024):
        raise FixtureValidationError("invalid expected source digest set")

    expected_sources = set()
    for digest in expected_source_sha256s:
        if type(digest) is not str or not _SHA256.fullmatch(digest):
            raise FixtureValidationError("invalid expected source SHA-256")
        expected_sources.add(digest)

    seen = set()
    total = 0
    digests = []
    for record in records:
        if type(record) is not dict or any(type(key) is not str for key in record):
            raise FixtureValidationError("invalid fixture fields")
        source_digest = record.get("source_sha256")
        if (type(source_digest) is not str
                or not _SHA256.fullmatch(source_digest)
                or source_digest not in expected_sources):
            raise FixtureValidationError("fixture source digest is not in expected source set")

        # Preflight the encoded length only for an exact built-in string.
        # A str subclass may override __len__; let the single-fixture
        # validator reject it before any caller-defined hook can execute.
        remaining = max_total_bytes - total
        payload_hex = record.get("payload_hex")
        if type(payload_hex) is str and len(payload_hex) > 2 * remaining:
            raise FixtureValidationError("batch byte limit exceeded")

        # The single-fixture validator requires a positive max_bytes value.
        # Use one only for the zero-remaining/empty-payload case above.
        fixture_limit = max(1, min(remaining, 1048576))
        payload = validate_packet_fixture(
            record,
            expected_source_sha256=source_digest,
            max_bytes=fixture_limit,
        )
        digest = hashlib.sha256(payload).hexdigest()
        identity = (source_digest, digest)
        if identity in seen:
            raise FixtureValidationError("duplicate fixture")
        seen.add(identity)
        total += len(payload)
        digests.append(digest)
    return {"count": len(digests), "total_bytes": total, "payload_sha256": tuple(digests)}
