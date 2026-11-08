"""Bounded, metadata-only validation of offline evidence batches.

Synthetic bookkeeping only; does not inspect APK bytes or infer wire protocols.
"""
from .offline_evidence_validation import EvidenceError, validate_record

MAX_RECORDS = 128


def validate_batch(records, *, require_verified=False):
    """Return immutable validated records, rejecting ambiguous duplicate identities."""
    if type(require_verified) is not bool:
        raise EvidenceError("require_verified must be boolean")
    if type(records) not in (list, tuple) or not 1 <= len(records) <= MAX_RECORDS:
        raise EvidenceError("invalid evidence batch size")
    result = []
    seen = set()
    for record in records:
        validated = validate_record(record)
        identity = (validated.kind, validated.sha256)
        if identity in seen:
            raise EvidenceError("duplicate evidence identity")
        if require_verified and not validated.verified:
            raise EvidenceError("unverified evidence in verified-only batch")
        seen.add(identity)
        result.append(validated)
    return tuple(result)
