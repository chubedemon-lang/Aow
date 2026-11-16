"""Evidence-only readiness gates for authorized offline APK research.

These gates NEVER imply APK interoperability or live network validation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from server.protocol_evidence_registry import Evidence, EvidenceError


STAGES = (
    "transport", "framing", "serialization", "handshake", "login", "session",
    "player", "map", "movement", "inventory", "shop", "combat", "quest",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

# Static APK inventory/decompilation/native analysis can verify a static fact,
# but cannot by itself prove the client-facing behavior represented by a stage.
# A gate is eligible only after a redacted fixture or local runtime trace from
# the unchanged authorized APK has been independently reproduced.
GATE_VERIFIED_METHODS = frozenset({"authorized_local_test"})


@dataclass(frozen=True)
class GateResult:
    stage: str
    ready: bool
    missing: tuple[str, ...]


def evidence_record_digest(record: Evidence) -> str:
    """Digest every public field for an operator-reviewed evidence allowlist.

    This stable digest binds approval to one exact record. It is not a
    signature and cannot authenticate the referenced fixture's origin.
    """
    if type(record) is not Evidence:
        raise EvidenceError("record must be an exact Evidence instance")
    payload = {
        "artifact_sha256": record.artifact_sha256,
        "method": record.method,
        "observation": record.observation,
        "reproduction": record.reproduction,
        "test_reference": record.test_reference,
        "topic": record.topic,
        "verified": record.verified,
    }
    encoded = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return hashlib.sha256(
        b"AOW-PROTOCOL-EVIDENCE-DIGEST-V1\0" + encoded
    ).hexdigest()


def evaluate_evidence(
    records: list[Evidence] | tuple[Evidence, ...],
    artifact_sha256: str | None = None,
    approved_evidence_digests: list[str] | tuple[str, ...] | frozenset[str] = (),
) -> tuple[GateResult, ...]:
    """Require eligible verified evidence for each stage from one artifact.

    If records contain multiple artifact fingerprints, callers must select one
    explicitly. Evidence from different APK builds must never be combined to
    unlock a downstream stage. Input records are provenance metadata, never
    packet bytes or secrets.

    A record's `verified` flag means its stated observation was reproduced by
    its declared method. It does not automatically make that observation
    sufficient for a protocol stage. Only `authorized_local_test` records can
    satisfy a stage gate, and only when the exact record digest is included in
    the caller-supplied operator-reviewed `approved_evidence_digests` list.
    The default list is empty, so no record unlocks a stage by itself. Static
    APK inventory, decompilation, and IL2CPP inspection remain useful evidence
    but cannot establish active transport, complete framing, handshake, login,
    or later client-facing behavior. A digest binds the record fields; it is
    not a signature or independent proof of fixture origin.

    The order is intentional: a downstream stage cannot be marked ready until
    the prior stages have eligible verified evidence from the same artifact.
    """
    if type(records) not in (list, tuple):
        raise EvidenceError("records must be a built-in list or tuple")
    if any(type(record) is not Evidence for record in records):
        raise EvidenceError("all records must be exact Evidence instances")
    if type(approved_evidence_digests) not in (list, tuple, frozenset):
        raise EvidenceError(
            "approved_evidence_digests must be a built-in list, tuple, or frozenset"
        )
    approved = set()
    for digest in approved_evidence_digests:
        if type(digest) is not str or not _SHA256.fullmatch(digest):
            raise EvidenceError("approved evidence digests must be lowercase SHA-256")
        if digest in approved:
            raise EvidenceError("duplicate approved evidence digest")
        approved.add(digest)

    fingerprints = {record.artifact_sha256 for record in records}
    if artifact_sha256 is None:
        if len(fingerprints) > 1:
            raise EvidenceError(
                "records span multiple artifacts; select artifact_sha256 explicitly"
            )
        selected_fingerprint = next(iter(fingerprints), None)
    else:
        if type(artifact_sha256) is not str or not _SHA256.fullmatch(artifact_sha256):
            raise EvidenceError("artifact_sha256 must be lowercase SHA-256")
        if artifact_sha256 not in fingerprints:
            raise EvidenceError("no evidence records match artifact_sha256")
        selected_fingerprint = artifact_sha256

    selected_records = (
        record for record in records
        if selected_fingerprint is not None
        and record.artifact_sha256 == selected_fingerprint
    )
    verified = {
        record.topic for record in selected_records
        if (
            record.verified
            and record.method in GATE_VERIFIED_METHODS
            and evidence_record_digest(record) in approved
        )
    }
    results = []
    for index, stage in enumerate(STAGES):
        missing = tuple(
            topic for topic in STAGES[:index + 1]
            if topic not in verified
        )
        results.append(GateResult(stage, not missing, missing))
    return tuple(results)
