"""Generic signed big-endian length-prefix hypothesis for offline stream analysis.

This helper is deliberately not AOW-specific. A caller must select the byte
offset to test. A successful parse is only a fit to that hypothesis; it does
not establish sender framing, field meaning, or compatibility.
"""

from .frame_reader import CallbackFrameReader


SUPPORTED_LENGTH_OFFSETS = (0, 4)
MAX_SIGNED_LENGTH = 0x7FFFFFFF


class InvalidCandidateLength(ValueError):
    """The selected signed 32-bit candidate length is negative."""


class CandidateLengthTooLarge(ValueError):
    """The selected candidate length exceeds the caller's safety bound."""

    def __init__(self, requested, limit):
        self.requested = requested
        self.limit = limit
        super().__init__(
            "candidate length " + str(requested)
            + " exceeds configured limit " + str(limit)
        )


def _validate_length_offset(length_offset):
    if type(length_offset) is not int or length_offset not in SUPPORTED_LENGTH_OFFSETS:
        raise ValueError("length_offset must be exactly 0 or 4")


def make_signed_be_length_candidate_probe(
    *, length_offset, max_payload_bytes
):
    """Return a bounded probe for one caller-selected signed BE32 length offset.

    Bytes before the selected length field are treated as opaque candidate
    prefix bytes. They are included in the returned total frame size, but no
    message-ID or other semantics are assigned to them.
    """
    _validate_length_offset(length_offset)
    if (
        type(max_payload_bytes) is not int
        or not 0 <= max_payload_bytes <= MAX_SIGNED_LENGTH
    ):
        raise ValueError("max_payload_bytes must be in range 0..2147483647")

    header_size = length_offset + 4

    def probe(prefix):
        if type(prefix) is not bytes:
            raise TypeError("candidate probe prefix must be immutable bytes")
        if len(prefix) < header_size:
            return None
        length = int.from_bytes(
            prefix[length_offset:header_size], "big", signed=True
        )
        if length < 0:
            raise InvalidCandidateLength(
                "candidate signed length must be non-negative"
            )
        if length > max_payload_bytes:
            raise CandidateLengthTooLarge(length, max_payload_bytes)
        return header_size + length

    return probe


def make_signed_be_length_candidate_reader(
    *, length_offset, max_payload_bytes, max_buffer_bytes
):
    """Create a generic bounded reader for the selected BE32 length hypothesis.

    The effective payload bound is the smaller of the caller's payload limit
    and the available buffer space after the candidate prefix. No socket is
    opened and no protocol adapter is enabled.
    """
    _validate_length_offset(length_offset)
    header_size = length_offset + 4
    if type(max_buffer_bytes) is not int or max_buffer_bytes < header_size:
        raise ValueError(
            "max_buffer_bytes must be an integer of at least "
            + str(header_size)
        )
    # Validate the caller's payload limit before deriving the tighter bound.
    make_signed_be_length_candidate_probe(
        length_offset=length_offset,
        max_payload_bytes=max_payload_bytes,
    )
    effective_payload_limit = min(
        max_payload_bytes, max_buffer_bytes - header_size
    )
    probe = make_signed_be_length_candidate_probe(
        length_offset=length_offset,
        max_payload_bytes=effective_payload_limit,
    )
    return CallbackFrameReader(
        probe,
        max_frame_bytes=header_size + effective_payload_limit,
        max_buffer_bytes=max_buffer_bytes,
        max_probe_bytes=header_size,
    )
