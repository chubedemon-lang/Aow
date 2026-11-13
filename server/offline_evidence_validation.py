"""Offline evidence metadata validator. Never stores APK or packet payloads.

This is a provenance gate, not a parser for the original AOW protocol.
"""
import re
from dataclasses import dataclass

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED = frozenset({"apk", "local_capture", "decompiled_symbol", "test_observation"})

# Public provenance text must not leak network locations or sensitive material.
# Keep local repository/file references usable (for example docs/PROTOCOL.md).
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
_LOCAL_FILE_SUFFIXES = frozenset({
    "apk", "bat", "c", "cfg", "cpp", "cs", "css", "csv", "dll", "go",
    "h", "html", "ini", "java", "js", "json", "log", "md", "py", "ps1",
    "rst", "sh", "so", "sql", "toml", "ts", "txt", "xml", "yaml", "yml",
})
# Absolute paths can disclose usernames, private workspace layout, or the
# location of captures even when no network host or credential is present.
# Repository-relative references remain usable and are intentionally not
# matched by these patterns.
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"/(?:[^/\s]+/)*[^/\s]+"
    r"|[A-Za-z]:[\\/][^\s]+"
    r"|\\\\[^\\/\s]+[\\/][^\s]+"
    r")"
)
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
    pass


@dataclass(frozen=True)
class EvidenceRecord:
    kind: str
    sha256: str
    source: str
    observation: str
    verified: bool


def _contains_network_locator(value):
    if (
        _URI_SCHEME.search(value)
        or _IPV4.search(value)
        or _IPV6.search(value)
        or _LOCALHOST.search(value)
        or "@" in value
    ):
        return True
    for match in _HOSTNAME.finditer(value):
        suffix = match.group(0).rsplit(".", 1)[-1].split(":", 1)[0].lower()
        if suffix not in _LOCAL_FILE_SUFFIXES:
            return True
    return False


def _contains_sensitive_material(value):
    return (
        _contains_network_locator(value)
        or _ABSOLUTE_PATH.search(value) is not None
        or _CREDENTIAL_ASSIGNMENT.search(value) is not None
        or _BEARER_VALUE.search(value) is not None
        or _PACKET_BYTES.search(value) is not None
        or _PRIVATE_KEY.search(value) is not None
    )


def validate_record(record):
    """Validate one non-sensitive, locally sourced evidence record.

    Unknown, incomplete, or unverified claims cannot be marked as verified.
    No bytes, endpoints, tokens, absolute file paths, or proprietary material
    are accepted here.
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
        if _contains_sensitive_material(value):
            raise EvidenceError("sensitive locator or material in " + field)
    if type(record["verified"]) is not bool:
        raise EvidenceError("verified must be boolean")
    if record["verified"] and (
        record["source"].strip() == "" or record["observation"].strip() == ""
    ):
        raise EvidenceError("verified evidence requires provenance")
    return EvidenceRecord(**record)
