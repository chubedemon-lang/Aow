"""Offline protocol evidence metadata validation (no APK or packet bytes stored).

This module does not discover, decode, or assert any AOW wire protocol.
Evidence is only 'verified' when an authorized local reproducible test is
recorded. Never commit private capture contents, endpoints or credentials.
"""
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_KINDS = frozenset({
    "transport", "framing", "handshake", "login", "session",
    "player", "map", "movement", "inventory", "shop", "combat", "quest"
})
ALLOWED_STATUS = frozenset({"unverified", "verified", "rejected"})
MAX_MANIFEST_RECORDS = 4096
FIELDS = frozenset({
    "id", "kind", "status", "artifact_sha256", "method",
    "reproduction", "test_reference", "notes"
})


class EvidenceError(ValueError):
    """Invalid or unverifiable evidence metadata."""


def validate_record(record):
    """Return sanitized, schema-limited metadata for an offline evidence record.

    Hashes are identifiers, not proof of compatibility. This rejects unknown
    fields to avoid accidentally persisting raw captures or secrets.
    """
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise EvidenceError("record must have exactly the approved metadata fields")
    result = {}
    for key in ("id", "method", "reproduction", "test_reference", "notes"):
        value = record[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 512:
            raise EvidenceError("invalid metadata field: " + key)
        if not value.isprintable():
            raise EvidenceError("control character in metadata")
        result[key] = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", result["id"]):
        raise EvidenceError("invalid evidence id")
    for key, choices in (("kind", ALLOWED_KINDS), ("status", ALLOWED_STATUS)):
        if type(record[key]) is not str or record[key] not in choices:
            raise EvidenceError("invalid " + key)
        result[key] = record[key]
    digest = record["artifact_sha256"]
    if type(digest) is not str or SHA256.fullmatch(digest) is None:
        raise EvidenceError("invalid artifact SHA256")
    result["artifact_sha256"] = digest
    if result["status"] == "verified":
        if result["test_reference"].lower() in {"none", "n/a", "unknown", "pending"}:
            raise EvidenceError("verified evidence requires reproducible test reference")
        if result["reproduction"].lower() in {"none", "n/a", "unknown", "pending"}:
            raise EvidenceError("verified evidence requires reproduction instructions")
    return result


def validate_manifest(records):
    """Validate metadata-only manifest; reject duplicate evidence identifiers."""
    if not isinstance(records, list):
        raise EvidenceError("manifest must be a list")
    if len(records) > MAX_MANIFEST_RECORDS:
        raise EvidenceError("manifest exceeds maximum record count")
    seen = set()
    output = []
    for record in records:
        item = validate_record(record)
        if item["id"] in seen:
            raise EvidenceError("duplicate evidence id")
        seen.add(item["id"])
        output.append(item)
    return output
