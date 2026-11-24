"""Bounded, synthetic 4-byte big-endian length framing for offline fixture tests.

NOT inferred from AOW APK. No real transport or packet compatibility is claimed.
"""
from __future__ import annotations


class FixtureFrameError(ValueError):
    """Malformed or oversized synthetic fixture frame."""


class FixtureFrameDecoder:
    def __init__(self, max_payload: int = 65536) -> None:
        if type(max_payload) is not int or not 1 <= max_payload <= 1048576:
            raise FixtureFrameError("invalid max_payload")
        self.max_payload = max_payload
        self._buffer = bytearray()
        self._failed = False

    def feed(self, chunk: bytes) -> list[bytes]:
        if self._failed:
            raise FixtureFrameError("decoder failed; create a new decoder")
        if type(chunk) is not bytes:
            raise FixtureFrameError("chunk must be bytes")
        # Consume one frame at a time: a coalesced network read must not
        # cause the retained buffer to grow with the entire read size.
        frames = []
        offset = 0
        while offset < len(chunk):
            if len(self._buffer) < 4:
                take = min(4 - len(self._buffer), len(chunk) - offset)
                self._buffer.extend(chunk[offset:offset + take])
                offset += take
                if len(self._buffer) < 4:
                    break
            size = int.from_bytes(self._buffer[:4], "big")
            if size == 0 or size > self.max_payload:
                self._buffer.clear()
                self._failed = True
                raise FixtureFrameError("invalid frame size")
            remaining = 4 + size - len(self._buffer)
            take = min(remaining, len(chunk) - offset)
            self._buffer.extend(chunk[offset:offset + take])
            offset += take
            if len(self._buffer) == 4 + size:
                frames.append(bytes(self._buffer[4:]))
                self._buffer.clear()
        return frames

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer)


def encode_fixture_frame(payload: bytes, max_payload: int = 65536) -> bytes:
    if type(max_payload) is not int or not 1 <= max_payload <= 1048576:
        raise FixtureFrameError("invalid max_payload")
    if type(payload) is not bytes or not 1 <= len(payload) <= max_payload:
        raise FixtureFrameError("invalid payload")
    return len(payload).to_bytes(4, "big") + payload
