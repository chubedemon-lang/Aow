"""Bounded *synthetic* framing harness, NOT the AOW APK wire format.

This deterministic test transport uses a 2-byte big-endian payload length.
It is deliberately isolated from the production protocol adapter until
authorized offline APK evidence establishes the actual framing contract.
"""


class FrameError(ValueError):
    """Invalid synthetic frame or resource limit exceeded."""


class SyntheticFrameDecoder:
    def __init__(self, max_payload=4096):
        if type(max_payload) is not int or not 1 <= max_payload <= 65535:
            raise ValueError("max_payload must be 1..65535")
        self.max_payload = max_payload
        self._buffer = bytearray()

    @property
    def buffered_bytes(self):
        return len(self._buffer)

    def feed(self, data):
        """Return complete payloads; retain partial bytes for the next feed.

        Reject oversized declared lengths immediately, even before the payload
        arrives. On any invalid length, clear buffered data and fail closed.
        """
        if not isinstance(data, bytes):
            raise TypeError("data must be immutable bytes")
        self._buffer.extend(data)
        frames = []
        while len(self._buffer) >= 2:
            size = int.from_bytes(self._buffer[:2], "big")
            if size == 0 or size > self.max_payload:
                self._buffer.clear()
                raise FrameError("invalid synthetic payload length")
            if len(self._buffer) < size + 2:
                break
            frames.append(bytes(self._buffer[2:size + 2]))
            del self._buffer[:size + 2]
        return frames


def encode_synthetic_frame(payload, max_payload=4096):
    """Encode a test fixture only; never use to claim APK compatibility."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be immutable bytes")
    if type(max_payload) is not int or not 1 <= max_payload <= 65535:
        raise ValueError("max_payload must be 1..65535")
    if not 1 <= len(payload) <= max_payload:
        raise FrameError("invalid synthetic payload length")
    return len(payload).to_bytes(2, "big") + payload
