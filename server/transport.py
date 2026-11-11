"""Evidence-gated transport boundary; no AOW packet format is assumed.

An adapter cannot parse or emit bytes until a separately reviewed protocol
contract is supplied. This module deliberately contains no network listener.
"""
from dataclasses import dataclass
import re
from typing import Callable


class UnverifiedProtocolError(RuntimeError):
    """The original APK wire format has not been established."""


_SAFE_REFERENCE = re.compile(r"[A-Za-z0-9_./:#-]{1,160}\\Z")
_SECRET_REFERENCE = re.compile(
    r"(?i)(?:token|secret|password|apikey|api_key|credential)"
)


@dataclass(frozen=True)
class ProtocolEvidence:
    source_digest: str
    observation: str
    review_reference: str

    def __post_init__(self):
        # A digest is an identifier, not a license to publish original APK data.
        if not isinstance(self.source_digest, str) or len(self.source_digest) != 64 or any(
            c not in "0123456789abcdef" for c in self.source_digest
        ):
            raise ValueError("source_digest must be lowercase SHA-256 hex")
        if (
            not isinstance(self.observation, str)
            or not self.observation.strip()
            or len(self.observation) > 2000
        ):
            raise ValueError("observation required (max 2000 characters)")
        reference = self.review_reference
        if (
            not isinstance(reference, str)
            or not _SAFE_REFERENCE.fullmatch(reference)
            or "://" in reference
            or "//" in reference
            or _SECRET_REFERENCE.search(reference)
        ):
            raise ValueError("review reference must be a sanitized local locator")


MAX_SYNTHETIC_PAYLOAD_BYTES = 1024 * 1024


class TransportAdapter:
    """Dependency-injected codec boundary, not an APK-compatible implementation."""

    def __init__(self, evidence=None, decode: Callable = None, encode: Callable = None):
        if evidence is not None and not isinstance(evidence, ProtocolEvidence):
            raise TypeError("invalid evidence")
        if (decode is None) != (encode is None):
            raise ValueError("encode and decode must be provided together")
        if decode is not None and (not callable(decode) or not callable(encode)):
            raise TypeError("codecs must be callable")
        self._evidence = evidence
        self._decode = decode
        self._encode = encode

    @property
    def configured(self):
        # This means only that a codec and evidence metadata were supplied.
        # It does NOT establish actual APK compatibility.
        return self._evidence is not None and self._decode is not None

    def receive(self, payload):
        if not self.configured:
            raise UnverifiedProtocolError("no reviewed protocol codec configured")
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > MAX_SYNTHETIC_PAYLOAD_BYTES:
            raise ValueError("payload exceeds local safety limit")
        return self._decode(payload)

    def send(self, message):
        if not self.configured:
            raise UnverifiedProtocolError("no reviewed protocol codec configured")
        payload = self._encode(message)
        if not isinstance(payload, bytes):
            raise TypeError("codec must return bytes")
        if len(payload) > MAX_SYNTHETIC_PAYLOAD_BYTES:
            raise ValueError("encoded payload exceeds local safety limit")
        return payload
