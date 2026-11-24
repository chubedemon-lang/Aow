"""Redacted metadata audit for privately supplied, authorized frame fixtures.

This utility applies an explicitly supplied generic FrameSpec. It does not
select or infer an AOW wire format and never returns or logs frame payloads.
"""
from dataclasses import dataclass
import hashlib
import re

from server.offline_frame_probe import FrameSpec, LengthFrameDecoder
from server.offline_packet_fixture import validate_packet_fixture


_SHA256 = re.compile(r"[0-9a-f]{64}\\Z")


class OfflineFrameAuditError(ValueError):
    """The bounded audit could not produce a complete frame summary."""


@dataclass(frozen=True)
class OfflineFrameAudit:
    """Deeply immutable, internally consistent summary of one decoded fixture."""

    source_sha256: str
    fixture_sha256: str
    frame_count: int
    wire_bytes: int
    header_bytes: int
    payload_bytes: int
    payload_sizes: tuple[int, ...]
    payload_sha256: tuple[str, ...]
    # (frame_start, payload_start, frame_end), zero-based/end-exclusive.
    frame_spans: tuple[tuple[int, int, int], ...]

    def __post_init__(self):
        """Validate the public constructor, not only the factory path.

        frozen dataclasses can still contain mutable values when constructed
        directly. Require exact tuples and prove that every reported offset,
        size and aggregate is mutually consistent before an instance exists.
        """
        for name in ("source_sha256", "fixture_sha256"):
            value = getattr(self, name)
            if type(value) is not str or not _SHA256.fullmatch(value):
                raise ValueError(f"invalid {name}")

        for name in ("frame_count", "wire_bytes", "header_bytes", "payload_bytes"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid {name}")

        for name in ("payload_sizes", "payload_sha256", "frame_spans"):
            if type(getattr(self, name)) is not tuple:
                raise TypeError(f"{name} must be an exact tuple")

        if not (
            self.frame_count == len(self.payload_sizes)
            == len(self.payload_sha256) == len(self.frame_spans)
        ):
            raise ValueError("frame summary counts do not match")

        if any(type(size) is not int or size < 0 for size in self.payload_sizes):
            raise ValueError("invalid payload size")
        if any(
            type(digest) is not str or not _SHA256.fullmatch(digest)
            for digest in self.payload_sha256
        ):
            raise ValueError("invalid payload SHA-256")

        previous_end = 0
        header_width = None
        calculated_header_bytes = 0
        calculated_payload_bytes = 0
        for index, (span, payload_size) in enumerate(
            zip(self.frame_spans, self.payload_sizes)
        ):
            if type(span) is not tuple or len(span) != 3:
                raise TypeError("each frame span must be an exact three-item tuple")
            frame_start, payload_start, frame_end = span
            if any(type(offset) is not int or offset < 0 for offset in span):
                raise ValueError("invalid frame span offset")
            width = payload_start - frame_start
            if width not in (1, 2, 4):
                raise ValueError("invalid frame header span")
            if header_width is None:
                header_width = width
            elif width != header_width:
                raise ValueError("inconsistent frame header widths")
            if frame_start != previous_end or frame_end < payload_start:
                raise ValueError("frame spans are not contiguous and ordered")
            if frame_end - payload_start != payload_size:
                raise ValueError("frame span does not match payload size")

            calculated_header_bytes += width
            calculated_payload_bytes += payload_size
            previous_end = frame_end

        if self.wire_bytes != previous_end:
            raise ValueError("wire byte count does not match final frame offset")
        if self.header_bytes != calculated_header_bytes:
            raise ValueError("header byte count does not match frame spans")
        if self.payload_bytes != calculated_payload_bytes:
            raise ValueError("payload byte count does not match payload sizes")
        if self.wire_bytes != self.header_bytes + self.payload_bytes:
            raise ValueError("wire byte accounting mismatch")


def audit_packet_fixture_frames(
    record,
    *,
    expected_source_sha256,
    spec,
    chunk_size=None,
    max_frames=4096,
    max_fixture_bytes=65536,
):
    """Validate and summarize a source-bound fixture using a caller's FrameSpec.

    The caller must independently establish both the source digest and the
    FrameSpec. The function validates fixture provenance/integrity, decodes
    the entire fixture with bounded incremental input, requires clean EOF,
    and returns only sizes, offsets and SHA-256 digests. Raw bytes are never returned,
    logged, or retained in the result.

    This is a generic offline audit helper, not an AOW packet decoder. A
    successful summary proves only that the supplied bytes are internally
    consistent with the caller-supplied generic framing configuration.
    """
    if type(spec) is not FrameSpec:
        raise TypeError("spec must be the exact FrameSpec type")
    if type(max_frames) is not int or not 1 <= max_frames <= 65536:
        raise ValueError("max_frames must be in range 1..65536")
    if type(max_fixture_bytes) is not int or not 1 <= max_fixture_bytes <= 1048576:
        raise ValueError("max_fixture_bytes must be in range 1..1048576")

    # The decoder reconstructs and revalidates the caller's frozen spec before
    # any fixture bytes are decoded. Use its detached validated snapshot below.
    decoder = LengthFrameDecoder(spec)
    validated_spec = decoder.spec
    if chunk_size is None:
        chunk_size = min(65536, validated_spec.max_chunk_bytes)
    if (
        type(chunk_size) is not int
        or not 1 <= chunk_size <= validated_spec.max_chunk_bytes
    ):
        raise ValueError("chunk_size must fit the validated decoder chunk limit")

    # Bound materialization per feed as well as the aggregate result count.
    # Reconstruct only from the decoder's already validated scalar snapshot.
    bounded_spec = FrameSpec(
        validated_spec.length_bytes,
        validated_spec.byteorder,
        validated_spec.includes_header,
        validated_spec.max_payload,
        validated_spec.max_chunk_bytes,
        min(validated_spec.max_frames_per_feed, max_frames),
    )
    decoder = LengthFrameDecoder(bounded_spec)

    payload = validate_packet_fixture(
        record,
        expected_source_sha256=expected_source_sha256,
        max_bytes=max_fixture_bytes,
    )
    fixture_sha256 = hashlib.sha256(payload).hexdigest()
    sizes = []
    digests = []
    spans = []
    next_frame_offset = 0
    for offset in range(0, len(payload), chunk_size):
        frames = decoder.feed(payload[offset:offset + chunk_size])
        if len(sizes) + len(frames) > max_frames:
            raise OfflineFrameAuditError("fixture exceeds maximum frame count")
        for frame in frames:
            sizes.append(len(frame))
            digests.append(hashlib.sha256(frame).hexdigest())
            frame_start = next_frame_offset
            payload_start = frame_start + validated_spec.length_bytes
            frame_end = payload_start + len(frame)
            spans.append((frame_start, payload_start, frame_end))
            next_frame_offset = frame_end

    # A partial prefix/body is an error; no partial summary escapes this call.
    decoder.finish()
    payload_bytes = sum(sizes)
    header_bytes = len(sizes) * validated_spec.length_bytes
    if (
        header_bytes + payload_bytes != len(payload)
        or next_frame_offset != len(payload)
    ):
        raise OfflineFrameAuditError("decoded frame accounting mismatch")

    return OfflineFrameAudit(
        source_sha256=expected_source_sha256,
        fixture_sha256=fixture_sha256,
        frame_count=len(sizes),
        wire_bytes=len(payload),
        header_bytes=header_bytes,
        payload_bytes=payload_bytes,
        payload_sizes=tuple(sizes),
        payload_sha256=tuple(digests),
        frame_spans=tuple(spans),
    )
