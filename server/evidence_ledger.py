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
# References are repository-local locators, never absolute artifact paths.
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"~[\\/][^\s]+"
    r"|/{1,}(?:[^/\s]+/)*[^/\s]+"
    r"|[A-Za-z]:[\\/][^\s]+"
    r"|\\\\[^\\/\s]+[\\/][^\s]+"
    r"|\\(?!\\)[^\\/\s]+(?:\\[^\\/\s]+)*"
    r")"
)
_PARENT_PATH = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")
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
    # SHA-256 of the sanitized manifest for one authorized local test run.
    # This groups evidence records; it is not an attestation by itself.
    test_run_sha256: str | None = None

    def __post_init__(self):
        # These records are later consumed by a readiness gate. Reject str
        # subclasses before regex, hashing, equality, or other string work so
        # caller-defined hooks cannot run while evidence is being validated.
        if type(self.apk_sha256) is not str or not _SHA256.fullmatch(self.apk_sha256):
            raise ValueError("apk_sha256 must be lowercase SHA-256")
        if type(self.topic) is not str or self.topic not in _ALLOWED_TOPICS:
            raise ValueError("unsupported evidence topic")
        if type(self.status) is not EvidenceStatus:
            raise TypeError("status must be EvidenceStatus")
        if (type(self.reference) is not str
                or not _REFERENCE.fullmatch(self.reference)
                or self.reference.startswith(("/", "\\"))
                or _ABSOLUTE_PATH.search(self.reference)
                or _PARENT_PATH.search(self.reference)
                or _contains_network_locator(self.reference)
                or re.search(r"(?i)(?:token|secret|password|apikey|api_key|credential)",
                             self.reference)):
            raise ValueError("reference must be a sanitized local source locator")
        if (type(self.method) is not str
                or self.method not in {"apk_zip_inventory", "jadx_offline",
                                        "il2cpp_offline", "synthetic_test",
                                        "authorized_local_test"}):
            raise ValueError("unknown observation method")
        if self.test_run_sha256 is not None and (
            type(self.test_run_sha256) is not str
            or not _SHA256.fullmatch(self.test_run_sha256)
        ):
            raise ValueError("test_run_sha256 must be lowercase SHA-256 when present")
        if self.status == EvidenceStatus.VERIFIED_END_TO_END:
            if self.method != "authorized_local_test":
                raise ValueError("end-to-end requires authorized local test")
            if self.test_run_sha256 is None:
                raise ValueError("end-to-end requires a test_run_sha256")


def protocol_ready(records, required=("transport", "framing", "serialization",
                                      "handshake", "login")):
    """Require all topics from one authorized run of ONE APK.

    Inputs are exact built-in collections and exact EvidenceRecord instances.
    A shared test_run_sha256 binds records to one sanitized local-run manifest;
    it is a grouping key, not an attestation. This checks bookkeeping only.
    """
    if type(records) not in (list, tuple):
        raise TypeError("records must be a built-in list or tuple")
    if type(required) not in (list, tuple):
        raise ValueError("required must be a built-in list or tuple")

    # Snapshot built-in containers once so concurrent caller mutation cannot
    # make separate topic checks observe different record sets.
    record_snapshot = tuple(records)
    required_snapshot = tuple(required)
    if any(type(record) is not EvidenceRecord for record in record_snapshot):
        raise TypeError("records must be exact EvidenceRecord instances")
    if not required_snapshot or any(
        type(topic) is not str or topic not in _ALLOWED_TOPICS
        for topic in required_snapshot
    ):
        raise ValueError("required must contain exact supported topic strings")

    required_topics = frozenset(required_snapshot)
    topics_by_run = {}
    for record in record_snapshot:
        if (record.status is EvidenceStatus.VERIFIED_END_TO_END
                and record.method == "authorized_local_test"):
            run_key = (record.apk_sha256, record.test_run_sha256)
            topics_by_run.setdefault(run_key, set()).add(record.topic)
    return any(
        required_topics.issubset(observed_topics)
        for observed_topics in topics_by_run.values()
    )
