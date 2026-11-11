"""Bounded, local-only evidence registry for protocol reverse-engineering.

No packets, IPs, or AOW compatibility are asserted by this module. A record
cannot be marked verified unless it carries a sanitized local test reference
and a reproducible command; synthetic-only tests never unlock protocol gates.
"""
from dataclasses import dataclass
import hashlib
import re


_SHA = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_TOPICS = frozenset({
    "transport", "framing", "serialization", "handshake", "login",
    "session", "player", "map", "movement", "inventory", "shop",
    "combat", "quest",
})
_VERIFIED_METHODS = frozenset({
    "apk_zip_inventory", "jadx_offline", "il2cpp_offline",
    "authorized_local_test",
})
_LOCAL_REFERENCE = re.compile(
    r"^(?:issue:[1-9][0-9]*|(?:docs|tests|server|tools)/[A-Za-z0-9_./#-]{1,150})$"
)
_REPRODUCTION = re.compile(r"^[A-Za-z0-9_./:# -]{1,512}$")
_URI_SCHEME = re.compile(r"\\b[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_IPV4 = re.compile(
    r"(?<![A-Za-z0-9_.])"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])"
    r"(?:\\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}"
    r"(?![A-Za-z0-9_.])"
)
_IPV6 = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)
_HOSTNAME = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+"
    r"[A-Za-z]{2,}(?::[0-9]{1,5})?"
    r"(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
_LOCALHOST = re.compile(
    r"(?<![A-Za-z0-9_.-])localhost(?::[0-9]{1,5})?(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_SECRET = re.compile(
    r"\\b(?:authorization|bearer|token|password|passwd|secret|"
    r"api[_-]?key|access[_-]?key|refresh[_-]?token)\\s*[:=]\\s*\\S+",
    re.IGNORECASE,
)
_RAW_BYTES = re.compile(r"\\b(?:packet|capture|payload)_bytes\\s*[:=]", re.IGNORECASE)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE
)
_LOCAL_FILE_SUFFIXES = frozenset({
    "apk", "bat", "c", "cfg", "cpp", "cs", "css", "csv", "dll", "go",
    "h", "html", "ini", "java", "js", "json", "log", "md", "py", "ps1",
    "rst", "sh", "so", "sql", "toml", "ts", "txt", "xml", "yaml", "yml",
})


class EvidenceError(ValueError):
    pass


def _contains_sensitive_material(value):
    if (
        _URI_SCHEME.search(value)
        or _IPV4.search(value)
        or _IPV6.search(value)
        or _LOCALHOST.search(value)
        or _SECRET.search(value)
        or _RAW_BYTES.search(value)
        or _PRIVATE_KEY.search(value)
    ):
        return True
    for match in _HOSTNAME.finditer(value):
        suffix = match.group(0).rsplit(".", 1)[-1].split(":", 1)[0].lower()
        if suffix not in _LOCAL_FILE_SUFFIXES:
            return True
    return False


def _validate_public_text(value, field, maximum=2000):
    if (
        type(value) is not str
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or not value.isprintable()
    ):
        raise EvidenceError(field + " must be printable, non-empty text")
    if _contains_sensitive_material(value):
        raise EvidenceError("sensitive locator or material in " + field)
    return value


def _validate_test_reference(value):
    if (
        type(value) is not str
        or _LOCAL_REFERENCE.fullmatch(value) is None
        or value.startswith("/")
        or "//" in value
        or any(part in {".", ".."} for part in value.split("/"))
        or _contains_sensitive_material(value)
    ):
        raise EvidenceError("test_reference must be a sanitized repository-local locator")
    return value


def _validate_reproduction(value):
    if (
        type(value) is not str
        or _REPRODUCTION.fullmatch(value) is None
        or value != value.strip()
        or "//" in value
        or any(part in {".", ".."} for part in value.split("/"))
        or _contains_sensitive_material(value)
    ):
        raise EvidenceError("reproduction must be a sanitized local command")
    return value


@dataclass(frozen=True)
class Evidence:
    topic: str
    artifact_sha256: str
    observation: str
    method: str
    verified: bool = False
    test_reference: str | None = None
    reproduction: str | None = None

    def __post_init__(self):
        if type(self.topic) is not str or self.topic not in ALLOWED_TOPICS:
            raise EvidenceError("unknown topic")
        if (
            not isinstance(self.artifact_sha256, str)
            or not _SHA.fullmatch(self.artifact_sha256)
        ):
            raise EvidenceError("invalid sha256")
        _validate_public_text(self.observation, "observation")
        _validate_public_text(self.method, "method", maximum=128)
        if type(self.verified) is not bool:
            raise EvidenceError("verified must be bool")
        if (self.test_reference is None) != (self.reproduction is None):
            raise EvidenceError("test_reference and reproduction must be provided together")
        if self.test_reference is not None:
            _validate_test_reference(self.test_reference)
            _validate_reproduction(self.reproduction)
        if self.verified:
            if self.method not in _VERIFIED_METHODS:
                raise EvidenceError("verified evidence requires an offline or authorized method")
            if self.test_reference is None:
                raise EvidenceError(
                    "verified evidence requires a local test reference and reproduction"
                )


class EvidenceRegistry:
    def __init__(self):
        self._records = []

    def add(self, record):
        if not isinstance(record, Evidence):
            raise EvidenceError("invalid record")
        if record in self._records:
            raise EvidenceError("duplicate evidence")
        self._records.append(record)

    def summary(self):
        return {
            topic: {
                "observations": sum(r.topic == topic for r in self._records),
                "verified": sum(
                    r.topic == topic and r.verified for r in self._records
                ),
            }
            for topic in sorted(ALLOWED_TOPICS)
        }

    @staticmethod
    def digest(data):
        if not isinstance(data, bytes):
            raise EvidenceError("bytes required")
        return hashlib.sha256(data).hexdigest()
