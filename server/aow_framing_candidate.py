"""Experimental receive-length framing candidate; not an AOW wire decoder.

A private static trace documented in docs/PROTOCOL.md indicates one Receiver.Cycle
branch reads four bytes, decodes a signed big-endian integer, and uses that
integer as the next read count. The value is compared with a static HTTP
marker. This module models only that candidate branch and rejects the marker
branch rather than guessing its response framing.

Do not connect this helper to a listener or original APK without a redacted,
authorized wire fixture for the exact client build.
"""

# Static constant recovered from the authorized APK's Receiver.Cycle branch.
# It does not prove that the HTTP branch is active for gameplay.
OBSERVED_HTTP_MARKER_VALUE = 0x48545450


class ReceiverLengthCandidateError(ValueError):
    """Base class for errors in the experimental receive-length candidate."""


class UnsupportedHttpMarkerBranch(ReceiverLengthCandidateError):
    """The four-byte value selected the separately handled HTTP-marker branch."""

    def __init__(self, marker_value):
        self.marker_value = marker_value
        super().__init__("HTTP-marker branch is not implemented by this candidate")


class InvalidReceiverLength(ReceiverLengthCandidateError):
    """The signed receive count is negative and cannot be read as a byte count."""

    def __init__(self, length):
        self.length = length
        super().__init__("candidate receive length must be non-negative")


class ReceiverPayloadTooLarge(ReceiverLengthCandidateError):
    """The candidate receive count exceeds the caller-supplied safety limit."""

    def __init__(self, requested, limit):
        self.requested = requested
        self.limit = limit
        super().__init__(
            f"candidate receive length {requested} exceeds configured limit {limit}"
        )


def make_four_byte_length_candidate_probe(
    *, max_payload_bytes, http_marker_value=OBSERVED_HTTP_MARKER_VALUE
):
    """Build a bounded probe for the documented four-byte receive-path candidate.

    The returned callback accepts immutable bytes and follows this *candidate*
    interpretation:

    - fewer than four bytes: return None;
    - first four bytes equal the statically observed HTTP marker by default:
      raise UnsupportedHttpMarkerBranch;
    - otherwise decode a signed big-endian 32-bit count and return 4 + count.

    The default marker is the static Receiver.Cycle constant 0x48545450 (ASCII
    "HTTP" in big-endian byte order). A caller may override it for synthetic
    tests or a separately reviewed client build. The 4 + count total is inferred
    from the initial four-byte read followed by a second read using the decoded
    count. The full outer frame, active runtime branch, HTTP response framing,
    compression placement and sender symmetry remain unverified. The caller
    must choose an independent resource limit; no AOW production limit is
    asserted here.
    """
    if type(http_marker_value) is not int or not -(1 << 31) <= http_marker_value < (1 << 31):
        raise ValueError("http_marker_value must fit signed 32-bit")
    if type(max_payload_bytes) is not int or not 0 <= max_payload_bytes <= 0x7FFFFFFF:
        raise ValueError("max_payload_bytes must be in range 0..2147483647")

    def probe(prefix):
        if type(prefix) is not bytes:
            raise TypeError("frame probe prefix must be immutable bytes")
        if len(prefix) < 4:
            return None

        value = int.from_bytes(prefix[:4], "big", signed=True)
        if value == http_marker_value:
            raise UnsupportedHttpMarkerBranch(value)
        if value < 0:
            raise InvalidReceiverLength(value)
        if value > max_payload_bytes:
            raise ReceiverPayloadTooLarge(value, max_payload_bytes)
        return 4 + value

    return probe
