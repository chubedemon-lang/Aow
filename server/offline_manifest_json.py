"""Bounded JSON ingestion for metadata-only offline protocol evidence.

No APK bytes, packet captures, endpoints, or credentials are stored here.
"""
import json

from server.offline_protocol_evidence import EvidenceError, validate_manifest

MAX_MANIFEST_JSON_BYTES = 2 * 1024 * 1024


def _unique_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value):
    raise EvidenceError("non-finite JSON number")


def load_manifest_json(payload):
    """Parse bounded UTF-8 JSON and validate metadata-only records.

    Rejects ambiguous duplicate keys and non-standard JSON constants.
    The caller is responsible for keeping the source file private.
    """
    if not isinstance(payload, bytes):
        raise EvidenceError("manifest JSON must be bytes")
    if len(payload) > MAX_MANIFEST_JSON_BYTES:
        raise EvidenceError("manifest JSON exceeds byte limit")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise EvidenceError("manifest JSON must be UTF-8") from exc
    try:
        records = json.loads(
            text, object_pairs_hook=_unique_object_pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise EvidenceError("invalid manifest JSON") from exc
    return validate_manifest(records)
