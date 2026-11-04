"""Sanitized, offline-only evidence ledger for APK protocol research.

This is a tracking format, not an AOW protocol implementation. Never store
extracted proprietary code, raw packets, credentials or endpoint strings here.
"""
from dataclasses import dataclass
from enum import Enum
import re


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9_./:#-]{1,160}$")
_ALLOWED_TOPICS = frozenset({"transport", "framing", "handshake", "login",
                             "session", "player", "map", "movement", "inventory",
                             "shop", "combat", "quest"})


class EvidenceStatus(str, Enum):
    UNKNOWN = "unknown"
    CANDIDATE = "candidate"
    VERIFIED_OFFLINE = "verified_offline"
    VERIFIED_END_TO_END = "verified_end_to_end"


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
        if not isinstance(self.reference, str) or not _REFERENCE.fullmatch(self.reference):
            raise ValueError("reference must be a sanitized source locator")
        if self.method not in {"apk_zip_inventory", "jadx_offline",
                               "il2cpp_offline", "synthetic_test",
                               "authorized_local_test"}:
            raise ValueError("unknown observation method")
        if self.status == EvidenceStatus.VERIFIED_END_TO_END and self.method != "authorized_local_test":
            raise ValueError("end-to-end requires authorized local test")


def protocol_ready(records, required=("transport", "framing", "handshake", "login")):
    """Only authorized end-to-end evidence can claim original-client readiness."""
    if not all(isinstance(record, EvidenceRecord) for record in records):
        raise TypeError("records must be EvidenceRecord instances")
    return all(any(r.topic == topic and r.status == EvidenceStatus.VERIFIED_END_TO_END
                   for r in records) for topic in required)
