"""Transport-neutral, synthetic length-prefix codec for offline server testing.

NOT an observed AOW packet format. No handshake, opcode or client assumptions.
"""
import struct


class FrameError(ValueError):
    pass


class LengthPrefixedFrames:
    """Unsigned big-endian 32-bit length, followed by opaque payload bytes."""

    def __init__(self, max_payload=1_048_576):
        if type(max_payload) is not int or not 1 <= max_payload <= 16_777_216:
            raise FrameError("invalid maximum")
        self.max_payload = max_payload
        self._buffer = bytearray()
        self._expected = None

    def encode(self, payload):
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= self.max_payload:
            raise FrameError("invalid payload")
        return struct.pack(">I", len(payload)) + payload

    def feed(self, chunk):
        if not isinstance(chunk, bytes):
            raise FrameError("invalid chunk")
        self._buffer.extend(chunk)
        frames = []
        while True:
            if self._expected is None:
                if len(self._buffer) < 4:
                    break
                size = struct.unpack(">I", self._buffer[:4])[0]
                if not 1 <= size <= self.max_payload:
                    self.reset()
                    raise FrameError("invalid frame length")
                del self._buffer[:4]
                self._expected = size
            if len(self._buffer) < self._expected:
                break
            frames.append(bytes(self._buffer[:self._expected]))
            del self._buffer[:self._expected]
            self._expected = None
        return tuple(frames)

    def reset(self):
        self._buffer.clear()
        self._expected = None
