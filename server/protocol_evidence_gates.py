"""Evidence-only readiness gates for authorized offline APK research.

These gates NEVER imply APK interoperability or live network validation.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from server.protocol_evidence_registry import Evidence, EvidenceError


STAGES = (
    "transport", "framing", "serialization", "handshake", "login", "session",
    "player", "map", "movement", "inventory", "shop", "combat", "quest",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class GateResult:
    stage: str
    ready: bool
    missing: tuple[str, ...]


def evaluate_evidence(
    records: list[Evidence] | tuple[Evidence, ...],
    artifact_sha256: str | None = None,
) -> tuple[GateResult, ...]:
    """Require verified evidence for each stage from one artifact.

    If records contain multiple artifact fingerprints, callers must select one
    explicitly. Evidence from different APK builds must never be combined to
    unlock a downstream stage. Input records are provenance metadata, never
    packet bytes or secrets.

    The order is intentional: a downstream stage cannot be marked ready until
    the prior stages have verified evidence from the same artifact.
    """
    if not isinstance(records, (list, tuple)):
        raise EvidenceError("records must be a list or tuple")
    if any(not isinstance(record, Evidence) for record in records):
        raise EvidenceError("all records must be Evidence instances")

    fingerprints = {record.artifact_sha256 for record in records}
    if artifact_sha256 is None:
        if len(fingerprints) > 1:
            raise EvidenceError(
                "records span multiple artifacts; select artifact_sha256 explicitly"
            )
        selected_fingerprint = next(iter(fingerprints), None)
    else:
        if not isinstance(artifact_sha256, str) or not _SHA256.fullmatch(artifact_sha256):
            raise EvidenceError("artifact_sha256 must be lowercase SHA-256")
        if artifact_sha256 not in fingerprints:
            raise EvidenceError("no evidence records match artifact_sha256")
        selected_fingerprint = artifact_sha256

    selected_records = (
        record for record in records
        if selected_fingerprint is not None
        and record.artifact_sha256 == selected_fingerprint
    )
    verified = {record.topic for record in selected_records if record.verified}
    results = []
    for index, stage in enumerate(STAGES):
        missing = tuple(
            topic for topic in STAGES[:index + 1]
            if topic not in verified
        )
        results.append(GateResult(stage, not missing, missing))
    return tuple(results)
