"""Sanitized, offline-only evidence ledger for APK protocol research.

This is a tracking format, not an AOW protocol implementation. Never store
extracted proprietary code, raw packets, credentials or endpoint strings here.
"""
from dataclasses import dataclass
from enum import Enum
import re


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9_./:#-]{1,160}$")
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
_HOST_PORT = re.compile(
    r"(?<![A-Za-z0-9_./-])([A-Za-z][A-Za-z0-9.-]*):([0-9]{1,5})(?![0-9])"
)
_LOCAL_FILE_SUFFIXES = frozenset({
    "apk", "bat", "c", "cfg", "cpp", "cs", "css", "csv", "dll", "go",
    "h", "html", "ini", "java", "js", "json", "log", "md", "py", "ps1",
    "rst", "sh", "so", "sql", "toml", "ts", "txt", "xml", "yaml", "yml",
})
_ALLOWED_REFERENCE_NAMESPACES = frozenset({"issue"})
_ALLOWED_TOPICS = frozenset({"transport", "framing", "serialization", "handshake", "login",
                             "session", "player", "map", "movement", "inventory",
                             "shop", "combat", "quest"})


class EvidenceStatus(str, Enum):
    UNKNOWN = "unknown"
    CANDIDATE = "candidate"
    VERIFIED_OFFLINE = "verified_offline"
    VERIFIED_END_TO_END = "verified_end_to_end"


def _contains_network_locator(value):
    """Conservatively reject endpoints while allowing repository file locators."""
    if (_URI_SCHEME.search(value) or _IPV4.search(value)
            or _IPV6.search(value) or _LOCALHOST.search(value)):
        return True
    for match in _HOSTNAME.finditer(value):
        suffix = match.group(0).rsplit(".", 1)[-1].split(":", 1)[0].lower()
        if suffix not in _LOCAL_FILE_SUFFIXES:
            return True
    for match in _HOST_PORT.finditer(value):
        host = match.group(1).lower()
        # Keep the established issue:<number> locator and path:line references.
        if host in _ALLOWED_REFERENCE_NAMESPACES:
            continue
        if match.start(1) > 0 and value[match.start(1) - 1] == "/":
            continue
        return True
    return False


@dataclass(frozen=True)
class EvidenceRecord:
    apk_sha256: str
    topic: str
    status: EvidenceStatus
    reference: str
    method: str

    def __post_init__(self):
        if not isinstance(self.apk_sha256, str) or not _SHA256.fullmatch(self.apk_sha256):
            raise ValueError("apk_sha256 must be lowercase SHA-256")
        if self.topic not in _ALLOWED_TOPICS:
            raise ValueError("unsupported evidence topic")
        if not isinstance(self.status, EvidenceStatus):
            raise TypeError("status must be EvidenceStatus")
        if (not isinstance(self.reference, str)
                or not _REFERENCE.fullmatch(self.reference)
                or _contains_network_locator(self.reference)
                or re.search(r"(?i)(?:token|secret|password|apikey|api_key|credential)",
                             self.reference)):
            raise ValueError("reference must be a sanitized local source locator")
        if self.method not in {"apk_zip_inventory", "jadx_offline",
                               "il2cpp_offline", "synthetic_test",
                               "authorized_local_test"}:
            raise ValueError("unknown observation method")
        if self.status == EvidenceStatus.VERIFIED_END_TO_END and self.method != "authorized_local_test":
            raise ValueError("end-to-end requires authorized local test")


def protocol_ready(records, required=("transport", "framing", "serialization",
                                      "handshake", "login")):
    """Require a complete authorized local test for ONE APK, never mixed APKs.

    This checks evidence bookkeeping only, not actual APK compatibility.
    """
    records = tuple(records)
    required = tuple(required)
    if not all(isinstance(record, EvidenceRecord) for record in records):
        raise TypeError("records must be EvidenceRecord instances")
    if not required or not all(topic in _ALLOWED_TOPICS for topic in required):
        raise ValueError("required must contain supported topics")
    return any(
        all(any(r.apk_sha256 == digest and r.topic == topic
                and r.status == EvidenceStatus.VERIFIED_END_TO_END
                and r.method == "authorized_local_test"
                for r in records) for topic in required)
        for digest in {r.apk_sha256 for r in records}
    )
