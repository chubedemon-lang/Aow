"""Evidence-derived AOW primitive payload codec.

This is deliberately not a packet/framing implementation and is not wired to
network handlers. It mirrors the statically inspected SimpleSerializer/
SimpleDeserializer primitive methods only.
"""


class AowPrimitiveWriter:
    """Build primitive payload bytes with an optional caller-selected cap.

    The cap is a local resource-safety setting, not a recovered AOW packet or
    message-size limit. The default remains unbounded until a caller supplies
    a limit supported by its own context.
    """

    def __init__(self, max_payload_bytes=None):
        if max_payload_bytes is not None and (
            type(max_payload_bytes) is not int or max_payload_bytes < 0
        ):
            raise ValueError("max_payload_bytes must be a non-negative integer or None")
        self._max_payload_bytes = max_payload_bytes
        self._buffer = bytearray()

    @property
    def size(self):
        """Number of payload bytes currently written."""
        return len(self._buffer)

    @property
    def max_payload_bytes(self):
        """Caller-selected local cap, or None when no cap was requested."""
        return self._max_payload_bytes

    @property
    def remaining_capacity(self):
        """Remaining bytes under the optional cap, or None when unbounded."""
        if self._max_payload_bytes is None:
            return None
        return self._max_payload_bytes - len(self._buffer)

    def _ensure_capacity(self, additional_bytes):
        if type(additional_bytes) is not int or additional_bytes < 0:
            raise ValueError("additional byte count must be a non-negative integer")
        if (
            self._max_payload_bytes is not None
            and additional_bytes > self._max_payload_bytes - len(self._buffer)
        ):
            raise ValueError("primitive payload exceeds configured byte limit")

    def _append(self, encoded):
        # All callers pass internally constructed immutable bytes. Check the
        # complete primitive before mutating the buffer so limit failures are
        # atomic from the caller's perspective.
        self._ensure_capacity(len(encoded))
        self._buffer.extend(encoded)
        return self

    def write_byte(self, value):
        if type(value) is not int or not 0 <= value <= 0xFF:
            raise ValueError("byte value must be in range 0..255")
        return self._append(bytes((value,)))

    def write_boolean(self, value):
        if type(value) is not bool:
            raise TypeError("boolean value must be bool")
        return self.write_byte(1 if value else 0)

    def write_char(self, value):
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise ValueError("char value must be in range 0..65535")
        return self._append(value.to_bytes(2, "big"))

    def write_short(self, value):
        if type(value) is not int or not -(1 << 15) <= value < (1 << 15):
            raise ValueError("short value must fit signed 16-bit")
        return self._append((value & 0xFFFF).to_bytes(2, "big"))

    def write_int(self, value):
        if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
            raise ValueError("int value must fit signed 32-bit")
        return self._append((value & 0xFFFFFFFF).to_bytes(4, "big"))

    def write_long(self, value):
        if type(value) is not int or not -(1 << 63) <= value < (1 << 63):
            raise ValueError("long value must fit signed 64-bit")
        return self._append((value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"))

    def write_string(self, value):
        if value is None:
            return self._append(b"\xff\xff")
        # Exact built-in strings keep encoding deterministic and avoid invoking
        # an overridden encode() method on a user-defined str subclass.
        if type(value) is not str:
            raise TypeError("string value must be str or None")

        # Preflight the UTF-16 code-unit limit before allocating the encoded
        # body. Python len() counts Unicode code points, so astral characters
        # need two UTF-16 units and require the bounded scan below.
        if len(value) >= 0x8000:
            raise ValueError("AOW string length must be below 32768 UTF-16 code units")
        code_units = 0
        for character in value:
            code_units += 2 if ord(character) > 0xFFFF else 1
            if code_units >= 0x8000:
                raise ValueError("AOW string length must be below 32768 UTF-16 code units")

        # Check the complete prefix + body before encoding or changing state.
        expected_size = 2 + code_units * 2
        self._ensure_capacity(expected_size)
        encoded = value.encode("utf-16-be", errors="surrogatepass")
        payload = code_units.to_bytes(2, "big") + encoded
        return self._append(payload)

    def to_bytes(self):
        return bytes(self._buffer)


class AowPrimitiveReader:
    def __init__(self, data):
        # Only exact built-in buffer types are accepted. Subclasses may override
        # __bytes__ and execute caller code while the reader snapshots input.
        if type(data) not in (bytes, bytearray, memoryview):
            raise TypeError("reader data must be bytes, bytearray, or memoryview")
        # Preserve immutable bytes without copying; snapshot mutable and strided inputs.
        raw = data if type(data) is bytes else bytes(data)
        self._data = memoryview(raw)
        self._offset = 0

    @property
    def offset(self):
        """Number of payload bytes consumed by this reader."""
        return self._offset

    @property
    def remaining(self):
        return len(self._data) - self._offset

    def _take(self, count):
        if type(count) is not int or count < 0:
            raise ValueError("read length must be a non-negative integer")
        end = self._offset + count
        if end > len(self._data):
            raise EOFError("truncated AOW primitive payload")
        result = self._data[self._offset:end].tobytes()
        self._offset = end
        return result

    def _read_u16(self):
        return int.from_bytes(self._take(2), "big")

    def _read_u32(self):
        return int.from_bytes(self._take(4), "big")

    def read_byte(self):
        return self._take(1)[0]

    def read_boolean(self):
        return self.read_byte() == 1

    def read_char(self):
        return self._read_u16()

    def read_short(self):
        value = self._read_u16()
        return value - 0x10000 if value & 0x8000 else value

    def read_int(self):
        # _take validates the full primitive before advancing the cursor.
        return int.from_bytes(self._take(4), "big", signed=True)

    def read_long(self):
        # A truncated fixed-width value must not consume a partial prefix.
        return int.from_bytes(self._take(8), "big", signed=True)

    def read_string(self):
        # The length prefix and its body form one logical primitive. If the
        # body is truncated, restore the cursor to the start of the string so
        # callers never observe a half-consumed value.
        start = self._offset
        try:
            code_units = self._read_u16()
            if code_units & 0x8000:
                return None
            raw = self._take(code_units * 2)
            return raw.decode("utf-16-be", errors="surrogatepass")
        except EOFError:
            self._offset = start
            raise

    def require_consumed(self):
        """Reject trailing bytes after a caller-defined primitive payload."""
        if self.remaining:
            raise ValueError("trailing bytes in primitive payload: " + str(self.remaining))
        return self
