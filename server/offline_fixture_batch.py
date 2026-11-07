"""Validate an in-memory set of private offline fixtures without storing bytes.

No AOW protocol claims are made. Caller is responsible for keeping records private.
"""
import hashlib

from server.offline_packet_fixture import FixtureValidationError, validate_packet_fixture


def validate_fixture_batch(records, *, max_records=128, max_total_bytes=1048576):
    """Return summary digests only; reject duplicates and over-budget inputs.

    Each record is validated by the single-fixture validator. Payloads are never
    returned, logged, written, or included in exception messages.
    """
    if type(max_records) is not int or not 1 <= max_records <= 1024:
        raise FixtureValidationError("invalid max_records")
    if type(max_total_bytes) is not int or not 1 <= max_total_bytes <= 16777216:
        raise FixtureValidationError("invalid max_total_bytes")
    if not isinstance(records, (list, tuple)) or not 1 <= len(records) <= max_records:
        raise FixtureValidationError("invalid fixture count")
    seen = set()
    total = 0
    digests = []
    for record in records:
        # Limit each decoded fixture before allocating it.
        remaining = max_total_bytes - total
        if remaining < 1:
            raise FixtureValidationError("batch byte limit exceeded")
        payload = validate_packet_fixture(record, max_bytes=min(remaining, 1048576))
        digest = hashlib.sha256(payload).hexdigest()
        identity = (record["source_sha256"], digest)
        if identity in seen:
            raise FixtureValidationError("duplicate fixture")
        seen.add(identity)
        total += len(payload)
        digests.append(digest)
    return {"count": len(digests), "total_bytes": total, "payload_sha256": tuple(digests)}
