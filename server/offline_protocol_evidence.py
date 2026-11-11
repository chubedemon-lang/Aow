"""Offline protocol evidence metadata validation (no APK or packet bytes stored).

This module does not discover, decode, or assert any AOW wire protocol.
Evidence is only 'verified' when an authorized local reproducible test is
recorded. Never commit private capture contents, endpoints or credentials.
"""
import re

from server.protocol_evidence_registry import ALLOWED_TOPICS

SHA256 = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_KINDS = ALLOWED_TOPICS
ALLOWED_STATUS = frozenset({"unverified", "verified", "rejected"})
MAX_MANIFEST_RECORDS = 4096
FIELDS = frozenset({
    "id", "kind", "status", "artifact_sha256", "method",
    "reproduction", "test_reference", "notes"
})

# Free-text metadata is intended for public provenance, not raw observations.
# Reject arbitrary URI schemes (not just HTTP), IPv4/IPv6 literals, localhost,
# and DNS-like hostnames before a caller writes metadata to a public manifest.
# This is a conservative guardrail, not a general-purpose DLP scanner.
_URI_SCHEME = re.compile(r"\b[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_IPV4 = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}"
    r"(?![A-Za-z0-9_.])"
)
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)
_HOSTNAME = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,}(?::[0-9]{1,5})?"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_LOCALHOST = re.compile(
    r"(?<![A-Za-z0-9_.-])localhost(?::[0-9]{1,5})?(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
# Local source references such as tests/test_module.py and docs/PROTOCOL.md
# are allowed; these suffixes are not treated as DNS top-level domains.
_LOCAL_FILE_SUFFIXES = frozenset({
    "apk", "bat", "c", "cfg", "cpp", "cs", "css", "csv", "dll", "go",
    "h", "html", "ini", "java", "js", "json", "log", "md", "py", "ps1",
    "rst", "sh", "so", "sql", "toml", "ts", "txt", "xml", "yaml", "yml",
})
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"\b(?:authorization|bearer|token|password|passwd|secret|"
    r"api[_-]?key|access[_-]?key|refresh[_-]?token)\s*[:=]\s*\S+",
    re.IGNORECASE,
)
_BEARER_VALUE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_PACKET_BYTES = re.compile(
    r"\b(?:packet|capture|payload)_bytes\s*[:=]", re.IGNORECASE
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
)


class EvidenceError(ValueError):
    """Invalid or unverifiable evidence metadata."""


def _contains_network_locator(value):
    if (_URI_SCHEME.search(value) or _IPV4.search(value)
            or _IPV6.search(value) or _LOCALHOST.search(value)):
        return True
    for match in _HOSTNAME.finditer(value):
        suffix = match.group(0).rsplit(".", 1)[-1].split(":", 1)[0].lower()
        if suffix not in _LOCAL_FILE_SUFFIXES:
            return True
    return False


def _validate_public_text(key, value):
    if not isinstance(value, str) or not value.strip() or len(value) > 512:
        raise EvidenceError("invalid metadata field: " + key)
    if not value.isprintable():
        raise EvidenceError("control character in metadata")
    if (_contains_network_locator(value)
            or _CREDENTIAL_ASSIGNMENT.search(value)
            or _BEARER_VALUE.search(value)
            or _PACKET_BYTES.search(value)
            or _PRIVATE_KEY.search(value)):
        raise EvidenceError(
            "sensitive endpoint, credential, or raw-byte marker in " + key
        )
    return value.strip()


def validate_record(record):
    """Return sanitized, schema-limited metadata for an offline evidence record.

    Hashes are identifiers, not proof of compatibility. Unknown fields and
    common secret/endpoint/raw-byte forms in free text are rejected to reduce
    accidental publication of private captures or credentials.
    """
    if not isinstance(record, dict) or set(record) != FIELDS:
        raise EvidenceError("record must have exactly the approved metadata fields")
    result = {}
    for key in ("id", "method", "reproduction", "test_reference", "notes"):
        result[key] = _validate_public_text(key, record[key])
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
