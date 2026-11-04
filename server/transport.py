"""Evidence-gated transport boundary; no AOW packet format is assumed.

An adapter cannot parse or emit bytes until a separately reviewed protocol
contract is supplied. This module deliberately contains no network listener.
"""
from dataclasses import dataclass
from typing import Callable


class UnverifiedProtocolError(RuntimeError):
    """The original APK wire format has not been established."""


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
        if not isinstance(self.observation, str) or not self.observation.strip():
            raise ValueError("observation required")
        if not isinstance(self.review_reference, str) or not self.review_reference.strip():
            raise ValueError("review reference required")


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
    def verified(self):
        # Having a review reference is necessary but not sufficient for real
        # compatibility; this only indicates that a codec has been wired.
        return self._evidence is not None and self._decode is not None

    def receive(self, payload):
        if not self.verified:
            raise UnverifiedProtocolError("no reviewed protocol codec configured")
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        return self._decode(payload)

    def send(self, message):
        if not self.verified:
            raise UnverifiedProtocolError("no reviewed protocol codec configured")
        payload = self._encode(message)
        if not isinstance(payload, bytes):
            raise TypeError("codec must return bytes")
        return payload
