"""Bounded, local-only evidence registry for protocol reverse-engineering.

No packets, IPs, or AOW compatibility are asserted by this module.
"""
from dataclasses import dataclass
import hashlib
import re


_SHA = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED = frozenset({\n    "transport", "framing", "handshake", "login", "session",\n    "player", "map", "movement", "inventory", "shop", "combat", "quest",\n})


class EvidenceError(ValueError):
    pass


@dataclass(frozen=True)
class Evidence:
    topic: str
    artifact_sha256: str
    observation: str
    method: str
    verified: bool = False

    def __post_init__(self):
        if self.topic not in _ALLOWED:
            raise EvidenceError("unknown topic")
        if not isinstance(self.artifact_sha256, str) or not _SHA.fullmatch(self.artifact_sha256):
            raise EvidenceError("invalid sha256")
        for field in (self.observation, self.method):
            if not isinstance(field, str) or not field.strip() or len(field) > 2000:
                raise EvidenceError("observation and method required (max 2000 chars)")
        if type(self.verified) is not bool:
            raise EvidenceError("verified must be bool")


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
        return {topic: {"observations": sum(r.topic == topic for r in self._records),
                        "verified": sum(r.topic == topic and r.verified for r in self._records)}
                for topic in sorted(_ALLOWED)}

    @staticmethod
    def digest(data):
        if not isinstance(data, bytes):
            raise EvidenceError("bytes required")
        return hashlib.sha256(data).hexdigest()
