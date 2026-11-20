"""Evidence-gated transport boundary; no AOW packet format is assumed.

An adapter cannot parse or emit bytes until a separately reviewed protocol
contract is supplied. This module deliberately contains no network listener.
"""
from dataclasses import dataclass
from typing import Callable

from server.protocol_evidence_registry import (
    EvidenceError,
    validate_local_evidence_reference,
    validate_public_evidence_text,
)
from server.protocol_evidence_gates import (
    STAGES,
    evaluate_evidence,
    evidence_record_digest,
)


class UnverifiedProtocolError(RuntimeError):
    """The original APK wire format has not been established."""

    def __init__(self, message, *, missing_stages=()):
        self.missing_stages = tuple(missing_stages)
        super().__init__(message)


@dataclass(frozen=True)
class ProtocolEvidence:
    source_digest: str
    observation: str
    review_reference: str

    def __post_init__(self):
        # A digest is an identifier, not a license to publish original APK data.
        # Require the exact built-in type before len()/iteration so a str
        # subclass cannot execute custom hooks during evidence validation.
        if (type(self.source_digest) is not str
                or len(self.source_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.source_digest)):
            raise ValueError("source_digest must be lowercase SHA-256 hex")
        try:
            validate_public_evidence_text(
                self.observation, field="observation", maximum=2000
            )
            validate_local_evidence_reference(self.review_reference)
        except EvidenceError as exc:
            raise ValueError(str(exc)) from exc


MAX_SYNTHETIC_PAYLOAD_BYTES = 1024 * 1024


class TransportAdapter:
    """Dependency-injected codec boundary, not an APK-compatible implementation."""

    def __init__(self, evidence=None, decode: Callable = None, encode: Callable = None):
        if evidence is not None and type(evidence) is not ProtocolEvidence:
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
        # Require the exact built-in type before invoking len() or the codec.
        # A bytes subclass can override __len__ and execute arbitrary code.
        if type(payload) is not bytes:
            raise TypeError("payload must be bytes")
        if len(payload) > MAX_SYNTHETIC_PAYLOAD_BYTES:
            raise ValueError("payload exceeds local safety limit")
        return self._decode(payload)

    def send(self, message):
        if not self.configured:
            raise UnverifiedProtocolError("no reviewed protocol codec configured")
        payload = self._encode(message)
        # Validate the codec result before invoking len() on caller-controlled
        # subclasses. Only an exact immutable bytes object crosses this boundary.
        if type(payload) is not bytes:
            raise TypeError("codec must return bytes")
        if len(payload) > MAX_SYNTHETIC_PAYLOAD_BYTES:
            raise ValueError("encoded payload exceeds local safety limit")
        return payload



class EvidenceGatedTransportAdapter(TransportAdapter):
    """Codec boundary enabled only by an approved evidence prefix.

    This class still does not open sockets or prove that the injected callbacks
    implement the observed wire contract. It prevents a future integration
    from treating arbitrary ProtocolEvidence metadata as sufficient readiness.
    """

    def __init__(
        self,
        *,
        records,
        artifact_sha256,
        approved_evidence_digests,
        decode,
        encode,
        required_through="serialization",
    ):
        if type(required_through) is not str or required_through not in STAGES:
            raise ValueError("required_through must be a known protocol stage")
        if type(records) not in (list, tuple):
            raise EvidenceError("records must be a built-in list or tuple")

        stage_index = STAGES.index(required_through)
        required_stages = STAGES[:stage_index + 1]
        if not records:
            raise UnverifiedProtocolError(
                "no protocol evidence records supplied",
                missing_stages=required_stages,
            )

        gates = evaluate_evidence(
            records,
            artifact_sha256=artifact_sha256,
            approved_evidence_digests=approved_evidence_digests,
        )
        selected_gate = gates[stage_index]
        if not selected_gate.ready:
            raise UnverifiedProtocolError(
                "protocol evidence is incomplete through "
                + required_through
                + ": "
                + ", ".join(selected_gate.missing),
                missing_stages=selected_gate.missing,
            )

        approved = set(approved_evidence_digests)
        terminal_record = next(
            (
                record for record in reversed(records)
                if (
                    record.artifact_sha256 == artifact_sha256
                    and record.topic == required_through
                    and record.verified
                    and record.method == "authorized_local_test"
                    and evidence_record_digest(record) in approved
                )
            ),
            None,
        )
        if terminal_record is None:
            # The ordered gate should make this unreachable, but keep the
            # constructor fail-closed if its implementation changes later.
            raise UnverifiedProtocolError(
                "approved terminal-stage evidence is unavailable",
                missing_stages=(required_through,),
            )

        super().__init__(
            ProtocolEvidence(
                terminal_record.artifact_sha256,
                terminal_record.observation,
                terminal_record.test_reference,
            ),
            decode=decode,
            encode=encode,
        )
        self._artifact_sha256 = artifact_sha256
        self._required_through = required_through
        self._gate_results = tuple(gates[:stage_index + 1])
        self._evidence_records = tuple(
            record for record in records
            if (
                record.artifact_sha256 == artifact_sha256
                and record.topic in required_stages
            )
        )

    @property
    def artifact_sha256(self):
        return self._artifact_sha256

    @property
    def required_through(self):
        return self._required_through

    @property
    def gate_results(self):
        """Ordered evidence readiness results through the selected stage."""
        return self._gate_results

    @property
    def evidence_records(self):
        """Selected artifact's records for the required stage prefix."""
        return self._evidence_records
