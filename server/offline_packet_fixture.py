"""Validate private, authorized offline packet fixtures without decoding AOW.

This module does not define, infer, or claim any APK wire protocol.
Fixture payload bytes must remain outside the public repository.
"""

import hashlib
import re

_SHA256 = re.compile(r"[0-9a-f]{64}\\Z")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*\\Z")


class FixtureValidationError(ValueError):
    """Invalid offline packet fixture or provenance."""


def validate_packet_fixture(
    record, *, expected_source_sha256, max_bytes=65536
):
    """Return immutable bytes only when fixture provenance is source-bound.

    expected_source_sha256 must come from the caller's trusted private
    inventory for the exact authorized APK or local capture being examined.
    The record's self-declared source digest must match it. This prevents a
    fixture from silently being replayed against a different client build.

    record fields: source_sha256, payload_hex, payload_sha256, verified.
    No fixture bytes are logged or persisted by this function. Matching a
    source digest and a payload digest validates provenance/integrity metadata;
    it does not prove packet semantics or APK/server compatibility. Empty
    payloads are valid byte sequences and are checked against SHA-256 of the
    empty byte string just like non-empty payloads.
    """
    if (type(expected_source_sha256) is not str
            or not _SHA256.fullmatch(expected_source_sha256)):
        raise FixtureValidationError("invalid expected source SHA-256")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1048576:
        raise FixtureValidationError("max_bytes out of range")
    if not isinstance(record, dict) or set(record) != {
        "source_sha256", "payload_hex", "payload_sha256", "verified"
    }:
        raise FixtureValidationError("invalid fixture fields")
    if record["verified"] is not True:
        raise FixtureValidationError("fixture requires explicit verification")

    for key in ("source_sha256", "payload_sha256"):
        value = record[key]
        if type(value) is not str or not _SHA256.fullmatch(value):
            raise FixtureValidationError("invalid SHA-256 metadata")
    if record["source_sha256"] != expected_source_sha256:
        raise FixtureValidationError("fixture source digest does not match expected artifact")

    value = record["payload_hex"]
    if not isinstance(value, str) or len(value) > 2 * max_bytes:
        raise FixtureValidationError("invalid fixture size")
    if not _HEX.fullmatch(value):
        raise FixtureValidationError("invalid payload hex")
    payload = bytes.fromhex(value)
    if hashlib.sha256(payload).hexdigest() != record["payload_sha256"]:
        raise FixtureValidationError("payload digest mismatch")
    return payload
