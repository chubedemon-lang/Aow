"""Evidence-only readiness gates for authorized offline APK research.

These gates NEVER imply APK interoperability or live network validation.
"""
from __future__ import annotations

from dataclasses import dataclass

from server.protocol_evidence_registry import Evidence, EvidenceError


STAGES = (
    "transport", "framing", "handshake", "login", "session",
    "player", "map", "movement", "inventory", "shop", "combat", "quest",
)


@dataclass(frozen=True)
class GateResult:
    stage: str
    ready: bool
    missing: tuple[str, ...]


def evaluate_evidence(records: list[Evidence] | tuple[Evidence, ...]) -> tuple[GateResult, ...]:
    """Require verified evidence for each stage and all its prerequisites.

    Input records are provenance metadata, never packet bytes or secrets.
    The order is intentional: a downstream stage cannot be marked ready
    until the prior stages have verified evidence.
    """
    if not isinstance(records, (list, tuple)):
        raise EvidenceError("records must be a list or tuple")
    if any(not isinstance(record, Evidence) for record in records):
        raise EvidenceError("all records must be Evidence instances")
    verified = {record.topic for record in records if record.verified}
    results = []
    for index, stage in enumerate(STAGES):
        missing = tuple(topic for topic in STAGES[:index + 1]
                        if topic not in verified)
        results.append(GateResult(stage, not missing, missing))
    return tuple(results)
