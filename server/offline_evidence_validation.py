"""Offline evidence metadata validator. Never stores APK or packet payloads.

This is a provenance gate, not a parser for the original AOW protocol.
"""
import re
from dataclasses import dataclass

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED = frozenset({"apk", "local_capture", "decompiled_symbol", "test_observation"})


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceRecord:
    kind: str
    sha256: str
    source: str
    observation: str
    verified: bool


def validate_record(record):
    """Validate one non-sensitive, locally sourced evidence record.

    Unknown, incomplete, or unverified claims cannot be marked as verified.
    No bytes, endpoints, tokens, or proprietary material are accepted here.
    """
    if not isinstance(record, dict) or set(record) != {
        "kind", "sha256", "source", "observation", "verified"
    }:
        raise EvidenceError("invalid evidence schema")
    kind, digest = record["kind"], record["sha256"]
    if type(kind) is not str or kind not in _ALLOWED:
        raise EvidenceError("unknown evidence kind")
    if type(digest) is not str or _SHA256.fullmatch(digest) is None:
        raise EvidenceError("invalid sha256")
    for field in ("source", "observation"):
        value = record[field]
        if type(value) is not str or not 1 <= len(value) <= 256:
            raise EvidenceError("invalid " + field)
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise EvidenceError("control character in " + field)
        if value != value.strip() or not value.strip():
            raise EvidenceError("invalid whitespace in " + field)
        # Keep public metadata free of URLs, network locations and credential hints.
        if re.search(r"(?i)(?:https?://|www\.|\b(?:token|password|secret|apikey|api_key)\s*[:=]|\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|@)", value):
            raise EvidenceError("sensitive locator in " + field)
    if type(record["verified"]) is not bool:
        raise EvidenceError("verified must be boolean")
    if record["verified"] and (
        record["source"].strip() == "" or record["observation"].strip() == ""
    ):
        raise EvidenceError("verified evidence requires provenance")
    return EvidenceRecord(**record)
