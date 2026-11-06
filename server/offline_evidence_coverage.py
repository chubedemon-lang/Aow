"""Metadata-only coverage summary for authorized offline protocol evidence.

No packet bytes, endpoint values, or inferred AOW protocol details are used.
"""
from server.offline_protocol_evidence import ALLOWED_KINDS, validate_manifest


def evidence_coverage(records):
    """Summarize evidence status by domain without treating unverified as proof."""
    validated = validate_manifest(records)
    counts = {kind: {"verified": 0, "unverified": 0, "rejected": 0}
              for kind in sorted(ALLOWED_KINDS)}
    for record in validated:
        counts[record["kind"]][record["status"]] += 1
    return {
        "domains": counts,
        "verified_domains": sorted(
            kind for kind, statuses in counts.items() if statuses["verified"] > 0
        ),
        "total_records": len(validated),
        "verified_records": sum(
            statuses["verified"] for statuses in counts.values()
        ),
    }
