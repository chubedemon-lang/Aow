"""Synthetic length-prefixed framing for local server tests only.

This is NOT a reverse-engineered AOW wire format.
"""
from __future__ import annotations

import struct


class FrameError(ValueError):
    """Invalid or oversized synthetic frame."""


class LengthPrefixedFrames:
    """Incremental unsigned 32-bit big-endian length-prefixed byte frames.

    A zero-length payload is permitted. Each instance owns a single stream.
    """

    def __init__(self, max_payload: int = 1_048_576, max_chunk_bytes: int = 1_048_576):
        if not isinstance(max_payload, int) or isinstance(max_payload, bool) or not 1 <= max_payload <= 0xFFFFFFFF:
            raise ValueError("max_payload must be an integer between 1 and 2**32-1")
        if type(max_chunk_bytes) is not int or max_chunk_bytes < 1:
            raise ValueError("max_chunk_bytes must be a positive integer")
        self.max_chunk_bytes = max_chunk_bytes
        self.max_payload = max_payload
        self._buffer = bytearray()

    def encode(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        if len(payload) > self.max_payload:
            raise FrameError("payload exceeds configured limit")
        return struct.pack(">I", len(payload)) + payload

    def feed(self, chunk: bytes) -> list[bytes]:
        if not isinstance(chunk, bytes):
            raise TypeError("chunk must be bytes")
        if len(chunk) > self.max_chunk_bytes:
            self._buffer.clear()
            raise FrameError("synthetic input chunk exceeds configured limit")
        self._buffer.extend(chunk)
        frames: list[bytes] = []
        offset = 0
        while len(self._buffer) - offset >= 4:
            size = struct.unpack_from(">I", self._buffer, offset)[0]
            if size > self.max_payload:
                self._buffer.clear()
                raise FrameError("declared frame length exceeds configured limit")
            if len(self._buffer) - offset - 4 < size:
                break
            start = offset + 4
            frames.append(bytes(self._buffer[start:start + size]))
            offset = start + size
        if offset:
            del self._buffer[:offset]
        return frames

    def reset(self) -> None:
        self._buffer.clear()
