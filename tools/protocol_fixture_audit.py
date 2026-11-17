"""Inspect a private authorized stream fixture without emitting packet bytes.

This tool exercises only the documented receive-side framing candidate. It does
not reassemble PCAPs, prove capture authorization, establish sender symmetry,
or verify APK compatibility. Keep fixture files outside the repository.
"""
import argparse
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


MAX_FIXTURE_BYTES = 20 * 1024 * 1024
MAX_JSON_NESTING = 64
MAX_CHUNK_BYTES = 1024 * 1024
MAX_TOTAL_STREAM_BYTES = 8 * 1024 * 1024
MAX_CHUNKS_PER_DIRECTION = 4096
MAX_BUFFER_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_PAYLOAD_BYTES = 1024 * 1024
DEFAULT_MAX_BUFFER_BYTES = DEFAULT_MAX_PAYLOAD_BYTES + 4
MAX_CANDIDATE_FRAMES = 4096
MAX_IO_EVENTS = MAX_CHUNKS_PER_DIRECTION * 2

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
_STREAM_KEYS = frozenset({"server_to_client", "client_to_server"})
_IO_EVENT_KEYS = frozenset({"direction", "offset", "length"})
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
    """Reject deeply nested JSON before the decoder builds nested objects."""
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise FixtureAuditError("fixture JSON nesting exceeds the configured depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise FixtureAuditError("fixture must be valid UTF-8 JSON")


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


def _validate_io_events(value, stream_bytes_by_direction):
    """Validate an operator-supplied chronological index over both byte streams.

    Each event describes one ordered local I/O observation as a contiguous
    range in the concatenated stream for its direction. The ranges must cover
    each direction exactly once, in per-direction byte order. This preserves
    the supplied cross-direction order without treating event boundaries as
    message boundaries or authenticating capture provenance.
    """
    if type(value) is not list:
        raise FixtureAuditError("io_events must be a built-in list")
    if not value:
        raise FixtureAuditError("io_events must contain observations for both directions")
    if len(value) > MAX_IO_EVENTS:
        raise FixtureAuditError("io_events exceeds the configured event limit")

    next_offsets = {direction: 0 for direction in _STREAM_DIRECTIONS}
    event_counts = {direction: 0 for direction in _STREAM_DIRECTIONS}
    previous_direction = None
    direction_switches = 0

    for index, event in enumerate(value):
        if type(event) is not dict or set(event) != _IO_EVENT_KEYS:
            raise FixtureAuditError(
                "io_events contains an invalid object at index " + str(index)
            )
        direction = event["direction"]
        if type(direction) is not str or direction not in next_offsets:
            raise FixtureAuditError(
                "io_events contains an invalid direction at index " + str(index)
            )
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

    return {
        "status": "operator_order_preserved_unverified",
        "event_count": len(value),
        "client_to_server_event_count": event_counts["client_to_server"],
        "server_to_client_event_count": event_counts["server_to_client"],
        "direction_switch_count": direction_switches,
    }


class _CandidateFrameCountLimit(FrameReaderError):
    """The redacted report reached its fixed candidate-frame count cap."""


def _collect_complete_frames(reader, frame_sizes):
    while True:
        frame = reader.read_frame()
        if frame is None:
            return
        if len(frame_sizes) >= MAX_CANDIDATE_FRAMES:
            raise _CandidateFrameCountLimit(
                "candidate frame report reached its configured count limit"
            )
        frame_sizes.append(len(frame))


def _inspect_receive_candidate(chunks, *, max_payload_bytes, max_buffer_bytes):
    # Account for the complete supplied stream, not only chunks reached before
    # a candidate error. This makes partial parses visibly fail closed.
    stream_bytes = sum(len(chunk) for chunk in chunks)
    reader = make_four_byte_length_candidate_reader(
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
    )
    frame_sizes = []
    try:
        for chunk in chunks:
            offset = 0
            while offset < len(chunk):
                _collect_complete_frames(reader, frame_sizes)
                available_room = reader.max_buffer_bytes - reader.available
                if available_room <= 0:
                    raise FrameReaderError("candidate reader cannot make progress")
                amount = min(available_room, len(chunk) - offset)
                reader.feed(chunk[offset:offset + amount])
                offset += amount
                _collect_complete_frames(reader, frame_sizes)

        reader.close()
        _collect_complete_frames(reader, frame_sizes)
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

    candidate_bytes_consumed = sum(frame_sizes)
    unclassified_stream_bytes = stream_bytes - candidate_bytes_consumed
    return {
        "status": status,
        "reason": reason,
        "frame_count": len(frame_sizes),
        "frame_count_is_lower_bound": truncated,
        "frame_sizes_truncated": truncated,
        "frame_sizes": frame_sizes,
        "candidate_bytes_consumed": candidate_bytes_consumed,
        "unclassified_stream_bytes": unclassified_stream_bytes,
        "candidate_stream_fully_consumed": (
            status == "candidate_frames_recovered" and unclassified_stream_bytes == 0
        ),
    }


def audit_fixture_bytes(
    content,
    *,
    expected_apk_sha256,
    max_payload_bytes=DEFAULT_MAX_PAYLOAD_BYTES,
    max_buffer_bytes=DEFAULT_MAX_BUFFER_BYTES,
    max_fixture_bytes=MAX_FIXTURE_BYTES,
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
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise FixtureAuditError("unsupported fixture schema version")
    expected_keys = (
        _FIXTURE_V1_KEYS if schema_version == 1 else _FIXTURE_V2_KEYS
    )
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
        )

    candidate = _inspect_receive_candidate(
        server_chunks,
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
    )
    candidate_status = candidate["status"]
    return {
        "status": (
            "candidate_analysis_only"
            if candidate_status == "candidate_frames_recovered"
            else "candidate_not_recovered"
        ),
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
        "client_to_server": {
            "chunk_count": len(client_chunks),
            "stream_bytes": client_bytes,
            "analysis": "not_attempted_sender_symmetry_unproven",
        },
        "exchange_order": exchange_order,
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
):
    """Read a private fixture safely and return only its redacted summary."""
    content = _read_regular_file_no_follow(path, max_fixture_bytes)
    return audit_fixture_bytes(
        content,
        expected_apk_sha256=expected_apk_sha256,
        max_payload_bytes=max_payload_bytes,
        max_buffer_bytes=max_buffer_bytes,
        max_fixture_bytes=max_fixture_bytes,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--max-payload-bytes", type=int, default=DEFAULT_MAX_PAYLOAD_BYTES)
    parser.add_argument("--max-buffer-bytes", type=int, default=DEFAULT_MAX_BUFFER_BYTES)
    parser.add_argument("--max-fixture-bytes", type=int, default=MAX_FIXTURE_BYTES)
    args = parser.parse_args(argv)

    try:
        result = inspect_fixture_file(
            args.fixture,
            expected_apk_sha256=args.apk_sha256,
            max_payload_bytes=args.max_payload_bytes,
            max_buffer_bytes=args.max_buffer_bytes,
            max_fixture_bytes=args.max_fixture_bytes,
        )
    except FixtureAuditError as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
