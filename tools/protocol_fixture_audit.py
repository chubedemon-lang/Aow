"""Inspect a private authorized stream fixture without emitting packet bytes.

This tool exercises only the documented receive-side framing candidate. It does
not reassemble PCAPs, prove capture authorization, establish sender symmetry,
or verify APK compatibility. Keep fixture files outside the repository.
"""
import argparse
import hashlib
import json
import os
import re
import stat

from server.aow_framing_candidate import (
    InvalidReceiverLength,
    ReceiverPayloadTooLarge,
    UnsupportedHttpMarkerBranch,
    make_four_byte_length_candidate_reader,
)
from server.frame_reader import FrameReaderError
from server.signed_be_length_candidate import (
    CandidateLengthTooLarge,
    InvalidCandidateLength,
    make_signed_be_length_candidate_reader,
)


MAX_FIXTURE_BYTES = 20 * 1024 * 1024
MAX_JSON_NESTING = 64
MAX_JSON_TOKENS = 100_000
MAX_CHUNK_BYTES = 1024 * 1024
MAX_TOTAL_STREAM_BYTES = 8 * 1024 * 1024
MAX_CHUNKS_PER_DIRECTION = 4096
MAX_BUFFER_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_PAYLOAD_BYTES = 1024 * 1024
DEFAULT_MAX_BUFFER_BYTES = DEFAULT_MAX_PAYLOAD_BYTES + 4
MAX_CANDIDATE_FRAMES = 4096
MAX_IO_EVENTS = MAX_CHUNKS_PER_DIRECTION * 2
MAX_CAPTURE_ELAPSED_NS = 24 * 60 * 60 * 1_000_000_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HEX_BYTES = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
_CAPTURE_KINDS = frozenset({
    "authorized_local_runtime",
    "authorized_local_packet_fixture",
})
_FIXTURE_BASE_KEYS = frozenset({
    "schema_version",
    "apk_sha256",
    "client_unchanged",
    "capture_kind",
    "streams",
})
_FIXTURE_V1_KEYS = _FIXTURE_BASE_KEYS
_FIXTURE_V2_KEYS = _FIXTURE_BASE_KEYS | {"io_events"}
_FIXTURE_V3_KEYS = _FIXTURE_V2_KEYS
_FIXTURE_V4_KEYS = _FIXTURE_V3_KEYS | {"observer_role"}
_STREAM_KEYS = frozenset({"server_to_client", "client_to_server"})
_IO_EVENT_KEYS = frozenset({"direction", "offset", "length"})
_IO_EVENT_V3_KEYS = _IO_EVENT_KEYS | {"elapsed_ns"}
_IO_EVENT_V4_KEYS = _IO_EVENT_V3_KEYS | {"operation"}
_IO_OPERATIONS = frozenset({"send", "receive"})
_OBSERVER_ROLES = frozenset({"client", "server"})
_STREAM_DIRECTIONS = ("client_to_server", "server_to_client")


class FixtureAuditError(ValueError):
    """The local fixture is malformed, unsafe, or outside configured limits."""


def _same_file_snapshot(left, right):
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _read_regular_file_no_follow(path, max_bytes):
    """Read one stable regular file through a no-follow descriptor."""
    if type(path) is not str or not path:
        raise FixtureAuditError("fixture path must be non-empty text")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FIXTURE_BYTES:
        raise FixtureAuditError("fixture size limit is invalid")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if nofollow is None or nonblock is None:
        raise FixtureAuditError(
            "platform does not support non-blocking no-follow fixture reads"
        )

    try:
        before = os.stat(path, follow_symlinks=False)
    except (OSError, ValueError) as exc:
        raise FixtureAuditError("fixture file cannot be inspected safely") from exc
    if not stat.S_ISREG(before.st_mode):
        raise FixtureAuditError("fixture must be a regular non-symlink file")
    if before.st_size > max_bytes:
        raise FixtureAuditError("fixture exceeds the configured size limit")

    # O_NONBLOCK is ignored for regular files, but prevents a path-swap race
    # from hanging forever if the final component becomes a FIFO before open.
    flags = os.O_RDONLY | nofollow | nonblock | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except (OSError, ValueError) as exc:
        raise FixtureAuditError("fixture file cannot be opened safely") from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_snapshot(before, opened):
            raise FixtureAuditError("fixture changed before it could be read")
        if opened.st_size > max_bytes:
            raise FixtureAuditError("fixture exceeds the configured size limit")

        content = bytearray()
        while len(content) <= max_bytes:
            remaining = max_bytes + 1 - len(content)
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > max_bytes:
            raise FixtureAuditError("fixture exceeds the configured size limit")

        after = os.fstat(descriptor)
        try:
            path_after = os.stat(path, follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise FixtureAuditError("fixture path changed during read") from exc
        if (
            not _same_file_snapshot(opened, after)
            or not _same_file_snapshot(after, path_after)
            or len(content) != opened.st_size
        ):
            raise FixtureAuditError("fixture changed while it was being read")
        return bytes(content)
    except OSError as exc:
        raise FixtureAuditError("fixture file could not be read safely") from exc
    finally:
        os.close(descriptor)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise FixtureAuditError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_value):
    raise FixtureAuditError("non-finite JSON values are not accepted")


def _validate_json_nesting(text):
    """Bound nesting and token count before json.loads builds Python objects."""
    depth = 0
    token_count = 0
    in_string = False
    escaped = False
    previous_character = None
    value_delimiters = " \t\r\n[{,:"
    primitive_starts = "-0123456789tfn"

    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            previous_character = character
            continue

        if character == '"':
            # Count object keys and string values as individual JSON tokens.
            token_count += 1
            in_string = True
        elif character in "[{":
            token_count += 1
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise FixtureAuditError("fixture JSON nesting exceeds the configured depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise FixtureAuditError("fixture must be valid UTF-8 JSON")
        elif (
            character in primitive_starts
            and (
                previous_character is None
                or previous_character in value_delimiters
            )
        ):
            # Count a number, true, false, or null once at its first character.
            token_count += 1

        if token_count > MAX_JSON_TOKENS:
            raise FixtureAuditError(
                "fixture JSON token count exceeds the configured limit"
            )
        previous_character = character


def _decode_chunks(
    value, field, *, remaining_total_bytes=MAX_TOTAL_STREAM_BYTES
):
    if type(remaining_total_bytes) is not int or not 0 <= remaining_total_bytes <= MAX_TOTAL_STREAM_BYTES:
        raise FixtureAuditError("remaining stream byte budget is invalid")
    if type(value) is not list:
        raise FixtureAuditError(field + " must be a built-in list")
    if len(value) > MAX_CHUNKS_PER_DIRECTION:
        raise FixtureAuditError(field + " has too many chunks")

    decoded = []
    total = 0
    for index, encoded in enumerate(value):
        if (
            type(encoded) is not str
            or len(encoded) > MAX_CHUNK_BYTES * 2
            or _HEX_BYTES.fullmatch(encoded) is None
        ):
            raise FixtureAuditError(
                field + " contains an invalid hexadecimal chunk at index " + str(index)
            )
        chunk_size = len(encoded) // 2
        if total + chunk_size > remaining_total_bytes:
            raise FixtureAuditError("combined stream data exceeds the configured limit")
        chunk = bytes.fromhex(encoded)
        if not chunk:
            raise FixtureAuditError(field + " contains an empty chunk")
        total += chunk_size
        decoded.append(chunk)
    return decoded, total


def _validate_io_events(
    value, stream_bytes_by_direction, *, include_timing=False,
    observer_role=None, include_operation=False,
):
    """Validate ordered I/O ranges, optionally with relative monotonic timing.

    Each event describes one local I/O observation as a contiguous range in
    that direction's concatenated stream. Event boundaries are observations,
    not packet/message boundaries. Schema v3 additionally carries elapsed
    monotonic nanoseconds relative to the first observation; only bounded
    overall and per-direction spans and maximum gaps are returned.
    """
    if type(value) is not list:
        raise FixtureAuditError("io_events must be a built-in list")
    if not value:
        raise FixtureAuditError("io_events must contain observations for both directions")
    if len(value) > MAX_IO_EVENTS:
        raise FixtureAuditError("io_events exceeds the configured event limit")

    if include_operation and (
        type(observer_role) is not str or observer_role not in _OBSERVER_ROLES
    ):
        raise FixtureAuditError("observer_role must be exactly client or server")
    expected_event_keys = (
        _IO_EVENT_V4_KEYS if include_operation
        else _IO_EVENT_V3_KEYS if include_timing
        else _IO_EVENT_KEYS
    )
    next_offsets = {direction: 0 for direction in _STREAM_DIRECTIONS}
    event_counts = {direction: 0 for direction in _STREAM_DIRECTIONS}
    operation_counts = {"send": 0, "receive": 0}
    previous_direction = None
    direction_switches = 0
    first_elapsed_ns = None
    previous_elapsed_ns = None
    max_inter_event_gap_ns = 0
    direction_timing = {
        direction: {
            "first_elapsed_ns": None,
            "last_elapsed_ns": None,
            "max_inter_event_gap_ns": 0,
        }
        for direction in _STREAM_DIRECTIONS
    }

    for index, event in enumerate(value):
        if type(event) is not dict or set(event) != expected_event_keys:
            raise FixtureAuditError(
                "io_events contains an invalid object at index " + str(index)
            )
        direction = event["direction"]
        if type(direction) is not str or direction not in next_offsets:
            raise FixtureAuditError(
                "io_events contains an invalid direction at index " + str(index)
            )
        if include_operation:
            operation = event["operation"]
            if type(operation) is not str or operation not in _IO_OPERATIONS:
                raise FixtureAuditError(
                    "io_events operation must be exactly send or receive"
                )
            if observer_role == "client":
                expected_direction = (
                    "client_to_server" if operation == "send"
                    else "server_to_client"
                )
            else:
                expected_direction = (
                    "server_to_client" if operation == "send"
                    else "client_to_server"
                )
            if direction != expected_direction:
                raise FixtureAuditError(
                    "io_events operation does not match observer role and direction"
                )
            operation_counts[operation] += 1
        offset = event["offset"]
        length = event["length"]
        if type(offset) is not int or offset < 0:
            raise FixtureAuditError(
                "io_events offset must be a non-negative integer"
            )
        if type(length) is not int or length <= 0:
            raise FixtureAuditError("io_events length must be a positive integer")
        if offset != next_offsets[direction]:
            raise FixtureAuditError(
                "io_events must cover each direction contiguously in observed order"
            )
        end = offset + length
        if end > stream_bytes_by_direction[direction]:
            raise FixtureAuditError(
                "io_events range exceeds its directional stream"
            )

        if include_timing:
            elapsed_ns = event["elapsed_ns"]
            if (
                type(elapsed_ns) is not int
                or not 0 <= elapsed_ns <= MAX_CAPTURE_ELAPSED_NS
            ):
                raise FixtureAuditError(
                    "io_events elapsed_ns must be a bounded non-negative integer"
                )
            if previous_elapsed_ns is None:
                if elapsed_ns != 0:
                    raise FixtureAuditError(
                        "io_events elapsed_ns must start at zero"
                    )
                first_elapsed_ns = elapsed_ns
            elif elapsed_ns < previous_elapsed_ns:
                raise FixtureAuditError(
                    "io_events elapsed_ns must be monotonic non-decreasing"
                )
            if previous_elapsed_ns is not None:
                max_inter_event_gap_ns = max(
                    max_inter_event_gap_ns,
                    elapsed_ns - previous_elapsed_ns,
                )
            previous_elapsed_ns = elapsed_ns

            directional = direction_timing[direction]
            if directional["last_elapsed_ns"] is None:
                directional["first_elapsed_ns"] = elapsed_ns
            else:
                directional["max_inter_event_gap_ns"] = max(
                    directional["max_inter_event_gap_ns"],
                    elapsed_ns - directional["last_elapsed_ns"],
                )
            directional["last_elapsed_ns"] = elapsed_ns

        next_offsets[direction] = end
        event_counts[direction] += 1
        if previous_direction is not None and direction != previous_direction:
            direction_switches += 1
        previous_direction = direction

    for direction in _STREAM_DIRECTIONS:
        if next_offsets[direction] != stream_bytes_by_direction[direction]:
            raise FixtureAuditError(
                "io_events must cover every byte in both stream directions"
            )

    summary = {
        "status": "operator_order_preserved_unverified",
        "event_count": len(value),
        "client_to_server_event_count": event_counts["client_to_server"],
        "server_to_client_event_count": event_counts["server_to_client"],
        "direction_switch_count": direction_switches,
    }
    if include_operation:
        summary.update({
            "observer_role_asserted": observer_role,
            "operation_semantics": "operator_asserted_unverified",
            "send_event_count": operation_counts["send"],
            "receive_event_count": operation_counts["receive"],
        })
    if include_timing:
        summary["timing"] = {
            "status": "relative_monotonic_summary_unverified",
            "event_span_ns": previous_elapsed_ns - first_elapsed_ns,
            "max_inter_event_gap_ns": max_inter_event_gap_ns,
            "per_direction": {
                direction: {
                    "event_count": event_counts[direction],
                    "event_span_ns": (
                        direction_timing[direction]["last_elapsed_ns"]
                        - direction_timing[direction]["first_elapsed_ns"]
                    ),
                    "max_inter_event_gap_ns": direction_timing[direction][
                        "max_inter_event_gap_ns"
                    ],
                }
                for direction in _STREAM_DIRECTIONS
            },
            "absolute_timestamps_emitted": False,
        }
    return summary


class _CandidateFrameCountLimit(FrameReaderError):
    """The redacted report reached its fixed candidate-frame count cap."""


def _collect_complete_frames(
    reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
):
    """Collect bounded sizes and cumulative end offsets for complete candidate frames.

    End offsets remain private to the audit calculation. They are used only to
    compare candidate frame boundaries with operator-supplied server-to-client
    I/O event ends; no offsets or bytes are emitted in the report.
    """
    while True:
        frame = reader.read_frame()
        if frame is None:
            return
        consumed_frame_bytes[0] += len(frame)
        if len(frame_sizes) >= MAX_CANDIDATE_FRAMES:
            raise _CandidateFrameCountLimit(
                "candidate frame report reached its configured count limit"
            )
        frame_sizes.append(len(frame))
        frame_end_offsets.append(consumed_frame_bytes[0])


def _inspect_receive_candidate(chunks, *, max_payload_bytes, max_buffer_bytes):
    # Account for the complete supplied stream, not only chunks reached before
    # a candidate error. This makes partial parses visibly fail closed.
    stream_bytes = sum(len(chunk) for chunk in chunks)
    reader = make_four_byte_length_candidate_reader(
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
    )
    frame_sizes = []
    frame_end_offsets = []
    consumed_frame_bytes = [0]
    try:
        for chunk in chunks:
            offset = 0
            while offset < len(chunk):
                _collect_complete_frames(
                    reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
                )
                available_room = reader.max_buffer_bytes - reader.available
                if available_room <= 0:
                    raise FrameReaderError("candidate reader cannot make progress")
                amount = min(available_room, len(chunk) - offset)
                reader.feed(chunk[offset:offset + amount])
                offset += amount
                _collect_complete_frames(
                    reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
                )

        reader.close()
        _collect_complete_frames(
            reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
        )
        status = "candidate_frames_recovered"
        reason = None
        truncated = False
    except (
        UnsupportedHttpMarkerBranch,
        InvalidReceiverLength,
        ReceiverPayloadTooLarge,
        FrameReaderError,
    ) as exc:
        truncated = isinstance(exc, _CandidateFrameCountLimit)
        status = "candidate_not_recovered"
        reason = "CandidateFrameCountLimit" if truncated else type(exc).__name__

    candidate_bytes_consumed = consumed_frame_bytes[0]
    unclassified_stream_bytes = stream_bytes - candidate_bytes_consumed
    return {
        "status": status,
        "reason": reason,
        "frame_count": len(frame_sizes),
        "frame_count_is_lower_bound": truncated,
        "frame_sizes_truncated": truncated,
        "frame_sizes": frame_sizes,
        "_frame_end_offsets": frame_end_offsets,
        "candidate_bytes_consumed": candidate_bytes_consumed,
        "unclassified_stream_bytes": unclassified_stream_bytes,
        "candidate_stream_fully_consumed": unclassified_stream_bytes == 0,
    }



def _inspect_signed_be_length_candidate(
    chunks, *, length_offset, max_payload_bytes, max_buffer_bytes
):
    """Test one explicitly selected generic BE32 length hypothesis.

    This is deliberately independent of the Receiver HTTP-marker candidate.
    It is never treated as evidence that Sender and Receiver are symmetric.
    """
    stream_bytes = sum(len(chunk) for chunk in chunks)
    reader = make_signed_be_length_candidate_reader(
        length_offset=length_offset,
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
    )
    frame_sizes = []
    frame_end_offsets = []
    consumed_frame_bytes = [0]
    try:
        for chunk in chunks:
            offset = 0
            while offset < len(chunk):
                _collect_complete_frames(
                    reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
                )
                available_room = reader.max_buffer_bytes - reader.available
                if available_room <= 0:
                    raise FrameReaderError("candidate reader cannot make progress")
                amount = min(available_room, len(chunk) - offset)
                reader.feed(chunk[offset:offset + amount])
                offset += amount
                _collect_complete_frames(
                    reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
                )

        reader.close()
        _collect_complete_frames(
            reader, frame_sizes, frame_end_offsets, consumed_frame_bytes
        )
        status = "candidate_frames_recovered"
        reason = None
        truncated = False
    except (
        InvalidCandidateLength,
        CandidateLengthTooLarge,
        FrameReaderError,
    ) as exc:
        truncated = isinstance(exc, _CandidateFrameCountLimit)
        status = "candidate_not_recovered"
        reason = type(exc).__name__

    candidate_bytes_consumed = consumed_frame_bytes[0]
    unclassified_stream_bytes = stream_bytes - candidate_bytes_consumed
    return {
        "status": status,
        "reason": reason,
        "frame_count": len(frame_sizes),
        "frame_count_is_lower_bound": truncated,
        "frame_sizes_truncated": truncated,
        "frame_sizes": frame_sizes,
        "_frame_end_offsets": frame_end_offsets,
        "candidate_bytes_consumed": candidate_bytes_consumed,
        "unclassified_stream_bytes": unclassified_stream_bytes,
        "candidate_stream_fully_consumed": unclassified_stream_bytes == 0,
    }


def _summarize_candidate_event_overlaps(
    frame_end_offsets, io_events, *, direction, schema_version, candidate_complete
):
    """Summarize frame/event interval overlap without exposing stream positions.

    Candidate frames and observed I/O events are contiguous, ordered partitions
    of their respective prefixes. A linear sweep counts overlaps, allowing the
    report to distinguish a candidate frame split across multiple I/O calls
    from one I/O call containing multiple candidate frames. These are local
    observation relationships only, never packet-boundary evidence.
    """
    unavailable = {
        "candidate_frames_overlapping_io_events": None,
        "candidate_frames_spanning_multiple_io_events": None,
        "io_events_overlapping_candidate_frames": None,
        "io_events_overlapping_multiple_candidate_frames": None,
        "io_events_without_complete_candidate_frame": None,
        "candidate_frames_without_io_event": None,
        "frame_event_overlap_pair_count": None,
    }
    if schema_version == 1:
        return {
            "status": "io_event_boundaries_not_recorded_schema_v1",
            **unavailable,
            "candidate_frame_set_complete": candidate_complete,
            "absolute_offsets_emitted": False,
            "packet_boundaries_verified": False,
        }

    event_ranges = tuple(
        (event["offset"], event["offset"] + event["length"])
        for event in io_events
        if event["direction"] == direction
    )
    frame_overlap_counts = [0] * len(frame_end_offsets)
    event_overlap_counts = [0] * len(event_ranges)

    frame_index = 0
    event_index = 0
    frame_start = 0
    while frame_index < len(frame_end_offsets) and event_index < len(event_ranges):
        frame_end = frame_end_offsets[frame_index]
        event_start, event_end = event_ranges[event_index]

        if frame_start < event_end and event_start < frame_end:
            frame_overlap_counts[frame_index] += 1
            event_overlap_counts[event_index] += 1

        if frame_end <= event_end:
            frame_start = frame_end
            frame_index += 1
        if event_end <= frame_end:
            event_index += 1

    return {
        "status": "unverified_candidate_frame_io_interval_overlap",
        "candidate_frames_overlapping_io_events": sum(
            count > 0 for count in frame_overlap_counts
        ),
        "candidate_frames_spanning_multiple_io_events": sum(
            count > 1 for count in frame_overlap_counts
        ),
        "io_events_overlapping_candidate_frames": sum(
            count > 0 for count in event_overlap_counts
        ),
        "io_events_overlapping_multiple_candidate_frames": sum(
            count > 1 for count in event_overlap_counts
        ),
        "io_events_without_complete_candidate_frame": sum(
            count == 0 for count in event_overlap_counts
        ),
        "candidate_frames_without_io_event": sum(
            count == 0 for count in frame_overlap_counts
        ),
        "frame_event_overlap_pair_count": sum(frame_overlap_counts),
        "candidate_frame_set_complete": candidate_complete,
        "absolute_offsets_emitted": False,
        "packet_boundaries_verified": False,
    }


def _summarize_receive_candidate_io_alignment(
    candidate, frame_end_offsets, io_events, *, schema_version
):
    """Correlate redacted candidate frame ends with observed S2C I/O event ends.

    I/O event boundaries describe local read/write observations, not packet
    boundaries. The summary emits counts only and never exposes stream offsets.
    """
    candidate_complete = (
        candidate["status"] == "candidate_frames_recovered"
        and candidate["candidate_stream_fully_consumed"]
        and not candidate["frame_count_is_lower_bound"]
    )
    frame_end_set = set(frame_end_offsets)
    if schema_version == 1:
        return {
            "status": "io_event_boundaries_not_recorded_schema_v1",
            "candidate_frame_boundary_count": len(frame_end_offsets),
            "candidate_frame_boundary_count_is_lower_bound": not candidate_complete,
            "server_to_client_io_event_boundary_count": None,
            "candidate_frame_boundaries_aligned_with_io_event_ends": None,
            "candidate_frame_boundaries_not_aligned_with_io_event_ends": None,
            "io_event_ends_aligned_with_known_candidate_frame_boundaries": None,
            "io_event_ends_without_known_candidate_frame_boundary": None,
            "candidate_boundary_set_complete": candidate_complete,
            "interval_overlap": _summarize_candidate_event_overlaps(
                frame_end_offsets,
                io_events,
                direction="server_to_client",
                schema_version=schema_version,
                candidate_complete=candidate_complete,
            ),
            "absolute_offsets_emitted": False,
            "packet_boundaries_verified": False,
        }

    server_event_ends = tuple(
        event["offset"] + event["length"]
        for event in io_events
        if event["direction"] == "server_to_client"
    )
    server_event_end_set = set(server_event_ends)
    aligned_frame_ends = sum(
        end_offset in server_event_end_set for end_offset in frame_end_offsets
    )
    aligned_io_ends = sum(
        end_offset in frame_end_set for end_offset in server_event_ends
    )
    return {
        "status": "unverified_candidate_io_boundary_correlation",
        "candidate_frame_boundary_count": len(frame_end_offsets),
        "candidate_frame_boundary_count_is_lower_bound": not candidate_complete,
        "server_to_client_io_event_boundary_count": len(server_event_ends),
        "candidate_frame_boundaries_aligned_with_io_event_ends": aligned_frame_ends,
        "candidate_frame_boundaries_not_aligned_with_io_event_ends": (
            len(frame_end_offsets) - aligned_frame_ends
        ),
        "io_event_ends_aligned_with_known_candidate_frame_boundaries": aligned_io_ends,
        "io_event_ends_without_known_candidate_frame_boundary": (
            len(server_event_ends) - aligned_io_ends
        ),
        "candidate_boundary_set_complete": candidate_complete,
        "interval_overlap": _summarize_candidate_event_overlaps(
            frame_end_offsets,
            io_events,
            direction="server_to_client",
            schema_version=schema_version,
            candidate_complete=candidate_complete,
        ),
        "absolute_offsets_emitted": False,
        "packet_boundaries_verified": False,
    }


def _summarize_client_candidate_io_alignment(
    candidate, frame_end_offsets, io_events, *, schema_version
):
    """Correlate redacted C2S candidate frame ends with observed C2S I/O ends.

    I/O event boundaries describe local write observations, not packet
    boundaries. The summary emits counts only and never exposes stream offsets.
    """
    candidate_complete = (
        candidate["status"] == "candidate_frames_recovered"
        and candidate["candidate_stream_fully_consumed"]
        and not candidate["frame_count_is_lower_bound"]
    )
    frame_end_set = set(frame_end_offsets)
    if schema_version == 1:
        return {
            "status": "io_event_boundaries_not_recorded_schema_v1",
            "candidate_frame_boundary_count": len(frame_end_offsets),
            "candidate_frame_boundary_count_is_lower_bound": not candidate_complete,
            "client_to_server_io_event_boundary_count": None,
            "candidate_frame_boundaries_aligned_with_io_event_ends": None,
            "candidate_frame_boundaries_not_aligned_with_io_event_ends": None,
            "io_event_ends_aligned_with_known_candidate_frame_boundaries": None,
            "io_event_ends_without_known_candidate_frame_boundary": None,
            "candidate_boundary_set_complete": candidate_complete,
            "interval_overlap": _summarize_candidate_event_overlaps(
                frame_end_offsets,
                io_events,
                direction="client_to_server",
                schema_version=schema_version,
                candidate_complete=candidate_complete,
            ),
            "absolute_offsets_emitted": False,
            "packet_boundaries_verified": False,
        }

    client_event_ends = tuple(
        event["offset"] + event["length"]
        for event in io_events
        if event["direction"] == "client_to_server"
    )
    client_event_end_set = set(client_event_ends)
    aligned_frame_ends = sum(
        end_offset in client_event_end_set for end_offset in frame_end_offsets
    )
    aligned_io_ends = sum(
        end_offset in frame_end_set for end_offset in client_event_ends
    )
    return {
        "status": "unverified_candidate_io_boundary_correlation",
        "candidate_frame_boundary_count": len(frame_end_offsets),
        "candidate_frame_boundary_count_is_lower_bound": not candidate_complete,
        "client_to_server_io_event_boundary_count": len(client_event_ends),
        "candidate_frame_boundaries_aligned_with_io_event_ends": aligned_frame_ends,
        "candidate_frame_boundaries_not_aligned_with_io_event_ends": (
            len(frame_end_offsets) - aligned_frame_ends
        ),
        "io_event_ends_aligned_with_known_candidate_frame_boundaries": aligned_io_ends,
        "io_event_ends_without_known_candidate_frame_boundary": (
            len(client_event_ends) - aligned_io_ends
        ),
        "candidate_boundary_set_complete": candidate_complete,
        "interval_overlap": _summarize_candidate_event_overlaps(
            frame_end_offsets,
            io_events,
            direction="client_to_server",
            schema_version=schema_version,
            candidate_complete=candidate_complete,
        ),
        "absolute_offsets_emitted": False,
        "packet_boundaries_verified": False,
    }


def audit_fixture_bytes(
    content,
    *,
    expected_apk_sha256,
    max_payload_bytes=DEFAULT_MAX_PAYLOAD_BYTES,
    max_buffer_bytes=DEFAULT_MAX_BUFFER_BYTES,
    max_fixture_bytes=MAX_FIXTURE_BYTES,
    client_to_server_length_offset=None,
    client_to_server_test_both_length_offsets=False,
):
    """Return a redacted candidate summary for a private stream fixture.

    The APK hash and unchanged-client flag are fixture assertions. This function
    compares the asserted hash with the operator-supplied expected fingerprint;
    it cannot authenticate the capture source or independently prove the APK
    was unchanged. Human review of provenance remains mandatory.
    """
    if type(content) is not bytes:
        raise FixtureAuditError("fixture content must be immutable bytes")
    if type(max_fixture_bytes) is not int or not 1 <= max_fixture_bytes <= MAX_FIXTURE_BYTES:
        raise FixtureAuditError("fixture size limit is invalid")
    if len(content) > max_fixture_bytes:
        raise FixtureAuditError("fixture exceeds the configured size limit")
    # Identify the exact private JSON artifact separately from the asserted
    # APK fingerprint.
    fixture_sha256 = hashlib.sha256(content).hexdigest()
    if (
        type(expected_apk_sha256) is not str
        or _SHA256.fullmatch(expected_apk_sha256) is None
    ):
        raise FixtureAuditError("expected APK fingerprint must be lowercase SHA-256")
    if (
        type(max_buffer_bytes) is not int
        or not 4 <= max_buffer_bytes <= MAX_BUFFER_BYTES
    ):
        raise FixtureAuditError("candidate buffer limit is invalid")
    if (
        type(max_payload_bytes) is not int
        or not 0 <= max_payload_bytes <= min(0x7FFFFFFF, max_buffer_bytes - 4)
    ):
        raise FixtureAuditError("candidate payload limit is invalid")
    if type(client_to_server_test_both_length_offsets) is not bool:
        raise FixtureAuditError(
            "client-to-server both-offset mode must be a boolean"
        )
    if client_to_server_test_both_length_offsets and client_to_server_length_offset is not None:
        raise FixtureAuditError(
            "select one client-to-server offset or both-offset mode, not both"
        )
    if client_to_server_test_both_length_offsets and max_buffer_bytes < 8:
        raise FixtureAuditError(
            "client-to-server both-offset mode requires at least 8 buffer bytes"
        )
    if client_to_server_length_offset is not None:
        if (
            type(client_to_server_length_offset) is not int
            or client_to_server_length_offset not in (0, 4)
        ):
            raise FixtureAuditError(
                "client-to-server candidate length offset must be exactly 0 or 4"
            )
        if max_buffer_bytes < client_to_server_length_offset + 4:
            raise FixtureAuditError(
                "client-to-server candidate buffer limit is smaller than its prefix"
            )

    try:
        text = content.decode("utf-8")
        _validate_json_nesting(text)
        document = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except FixtureAuditError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise FixtureAuditError("fixture must be valid UTF-8 JSON") from exc

    if type(document) is not dict:
        raise FixtureAuditError("fixture has an unsupported object shape")
    schema_version = document.get("schema_version")
    if type(schema_version) is not int or schema_version not in (1, 2, 3, 4):
        raise FixtureAuditError("unsupported fixture schema version")
    expected_keys = {
        1: _FIXTURE_V1_KEYS,
        2: _FIXTURE_V2_KEYS,
        3: _FIXTURE_V3_KEYS,
        4: _FIXTURE_V4_KEYS,
    }[schema_version]
    if set(document) != expected_keys:
        raise FixtureAuditError("fixture has an unsupported object shape")
    fixture_hash = document["apk_sha256"]
    if type(fixture_hash) is not str or _SHA256.fullmatch(fixture_hash) is None:
        raise FixtureAuditError("fixture APK fingerprint is invalid")
    if fixture_hash != expected_apk_sha256:
        raise FixtureAuditError("fixture APK fingerprint does not match the expected build")
    if document["client_unchanged"] is not True:
        raise FixtureAuditError("fixture must assert that the original client was unchanged")
    capture_kind = document["capture_kind"]
    if type(capture_kind) is not str or capture_kind not in _CAPTURE_KINDS:
        raise FixtureAuditError("fixture capture kind is not an authorized local kind")

    streams = document["streams"]
    if type(streams) is not dict or set(streams) != _STREAM_KEYS:
        raise FixtureAuditError("fixture must contain exactly both stream directions")
    server_chunks, server_bytes = _decode_chunks(
        streams["server_to_client"],
        "server_to_client",
        remaining_total_bytes=MAX_TOTAL_STREAM_BYTES,
    )
    if not server_chunks:
        raise FixtureAuditError("server_to_client must contain at least one chunk")
    client_chunks, client_bytes = _decode_chunks(
        streams["client_to_server"],
        "client_to_server",
        remaining_total_bytes=MAX_TOTAL_STREAM_BYTES - server_bytes,
    )
    if not client_chunks:
        raise FixtureAuditError(
            "client_to_server must contain at least one chunk"
        )

    if schema_version == 1:
        exchange_order = {
            "status": "not_recorded_schema_v1",
            "event_count": None,
            "client_to_server_event_count": None,
            "server_to_client_event_count": None,
            "direction_switch_count": None,
        }
    else:
        exchange_order = _validate_io_events(
            document["io_events"],
            {
                "server_to_client": server_bytes,
                "client_to_server": client_bytes,
            },
            include_timing=schema_version in (3, 4),
            observer_role=document.get("observer_role"),
            include_operation=schema_version == 4,
        )

    candidate = _inspect_receive_candidate(
        server_chunks,
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
    )
    frame_end_offsets = candidate.pop("_frame_end_offsets")
    receive_candidate_io_alignment = _summarize_receive_candidate_io_alignment(
        candidate,
        frame_end_offsets,
        document.get("io_events", ()),
        schema_version=schema_version,
    )
    client_candidate = None
    client_hypotheses = []
    client_candidate_io_alignment = {
        "status": "not_attempted_sender_symmetry_unproven",
        "candidate_frame_boundary_count": None,
        "candidate_frame_boundary_count_is_lower_bound": None,
        "client_to_server_io_event_boundary_count": None,
        "candidate_frame_boundaries_aligned_with_io_event_ends": None,
        "candidate_frame_boundaries_not_aligned_with_io_event_ends": None,
        "io_event_ends_aligned_with_known_candidate_frame_boundaries": None,
        "io_event_ends_without_known_candidate_frame_boundary": None,
        "candidate_boundary_set_complete": False,
        "absolute_offsets_emitted": False,
        "packet_boundaries_verified": False,
    }
    if client_to_server_test_both_length_offsets:
        client_candidate_io_alignment["status"] = (
            "not_applicable_multiple_independent_hypotheses"
        )

    selected_client_offsets = (
        (0, 4)
        if client_to_server_test_both_length_offsets
        else (
            ()
            if client_to_server_length_offset is None
            else (client_to_server_length_offset,)
        )
    )
    for selected_offset in selected_client_offsets:
        candidate_result = _inspect_signed_be_length_candidate(
            client_chunks,
            length_offset=selected_offset,
            max_payload_bytes=max_payload_bytes,
            max_buffer_bytes=max_buffer_bytes,
        )
        client_frame_end_offsets = candidate_result.pop("_frame_end_offsets")
        candidate_alignment = _summarize_client_candidate_io_alignment(
            candidate_result,
            client_frame_end_offsets,
            document.get("io_events", ()),
            schema_version=schema_version,
        )
        client_hypotheses.append({
            "length_field_offset_from_stream_start": selected_offset,
            "bytes_before_length_field_are_opaque": selected_offset == 4,
            "interpretation": "candidate_fit_does_not_prove_sender_symmetry",
            "candidate": candidate_result,
            "io_alignment": candidate_alignment,
        })
        if not client_to_server_test_both_length_offsets:
            client_candidate = candidate_result
            client_candidate_io_alignment = candidate_alignment
    candidate_status = candidate["status"]
    client_to_server_report = {
        "chunk_count": len(client_chunks),
        "stream_bytes": client_bytes,
        "analysis": (
            "not_attempted_sender_symmetry_unproven"
            if not client_hypotheses
            else "operator_selected_generic_signed_be32_length_hypotheses_only"
            if client_to_server_test_both_length_offsets
            else "operator_selected_generic_signed_be32_length_hypothesis_only"
        ),
    }
    if client_candidate is not None:
        client_to_server_report["length_prefix_candidate"] = {
            "length_field_offset_from_stream_start": client_to_server_length_offset,
            "bytes_before_length_field_are_opaque": client_to_server_length_offset == 4,
            "interpretation": "candidate_fit_does_not_prove_sender_symmetry",
            **client_candidate,
        }
    if client_to_server_test_both_length_offsets:
        client_to_server_report["hypothesis_comparison"] = "independent_no_ranking"
        client_to_server_report["length_prefix_hypotheses"] = client_hypotheses
    return {
        "status": (
            "candidate_analysis_only"
            if candidate_status == "candidate_frames_recovered"
            else "candidate_not_recovered"
        ),
        "fixture_sha256": fixture_sha256,
        "fixture_size_bytes": len(content),
        "apk_sha256": fixture_hash,
        "apk_fingerprint_match": True,
        "capture_kind": capture_kind,
        "client_unchanged_asserted": True,
        "authorization_independently_verified": False,
        "server_to_client": {
            "chunk_count": len(server_chunks),
            "stream_bytes": server_bytes,
            "receive_candidate": candidate,
        },
        "client_to_server": client_to_server_report,
        "sender_symmetry_verified": False,
        "exchange_order": exchange_order,
        "receive_candidate_io_alignment": receive_candidate_io_alignment,
        "client_to_server_candidate_io_alignment": client_candidate_io_alignment,
        "wire_contract_verified": False,
        "apk_compatible": False,
        "raw_bytes_emitted": False,
    }


def inspect_fixture_file(
    path,
    *,
    expected_apk_sha256,
    max_payload_bytes=DEFAULT_MAX_PAYLOAD_BYTES,
    max_buffer_bytes=DEFAULT_MAX_BUFFER_BYTES,
    max_fixture_bytes=MAX_FIXTURE_BYTES,
    client_to_server_length_offset=None,
    client_to_server_test_both_length_offsets=False,
):
    """Read a private fixture safely and return only its redacted summary."""
    content = _read_regular_file_no_follow(path, max_fixture_bytes)
    return audit_fixture_bytes(
        content,
        expected_apk_sha256=expected_apk_sha256,
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
        max_fixture_bytes=max_fixture_bytes,
        client_to_server_length_offset=client_to_server_length_offset,
        client_to_server_test_both_length_offsets=client_to_server_test_both_length_offsets,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--max-payload-bytes", type=int, default=DEFAULT_MAX_PAYLOAD_BYTES)
    parser.add_argument("--max-buffer-bytes", type=int, default=DEFAULT_MAX_BUFFER_BYTES)
    parser.add_argument("--max-fixture-bytes", type=int, default=MAX_FIXTURE_BYTES)
    parser.add_argument(
        "--client-to-server-length-offset",
        type=int,
        choices=(0, 4),
        default=None,
        help=(
            "opt-in generic signed-BE32 length hypothesis for the client-to-server "
            "stream; does not assert Sender/Receiver symmetry"
        ),
    )
    parser.add_argument(
        "--client-to-server-test-both-length-offsets",
        action="store_true",
        help=(
            "opt-in: test generic signed-BE32 length hypotheses at offsets 0 and 4 "
            "independently, without ranking them or asserting sender symmetry"
        ),
    )
    args = parser.parse_args(argv)

    try:
        result = inspect_fixture_file(
            args.fixture,
            expected_apk_sha256=args.apk_sha256,
            max_payload_bytes=args.max_payload_bytes,
            max_buffer_bytes=args.max_buffer_bytes,
            max_fixture_bytes=args.max_fixture_bytes,
            client_to_server_length_offset=args.client_to_server_length_offset,
            client_to_server_test_both_length_offsets=(
                args.client_to_server_test_both_length_offsets
            ),
        )
    except FixtureAuditError as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
