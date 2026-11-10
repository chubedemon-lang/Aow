"""Evidence-derived AOW primitive payload codec.

This is deliberately not a packet/framing implementation and is not wired to
network handlers. It mirrors the statically inspected SimpleSerializer/
SimpleDeserializer primitive methods only.
"""


class AowPrimitiveWriter:
    def __init__(self):
        self._buffer = bytearray()

    def write_byte(self, value):
        if type(value) is not int or not 0 <= value <= 0xFF:
            raise ValueError("byte value must be in range 0..255")
        self._buffer.append(value)
        return self

    def write_boolean(self, value):
        if type(value) is not bool:
            raise TypeError("boolean value must be bool")
        return self.write_byte(int(value) & 1)

    def write_char(self, value):
        if type(value) is not int or not 0 <= value <= 0xFFFF:
            raise ValueError("char value must be in range 0..65535")
        self._buffer.extend(value.to_bytes(2, "big"))
        return self

    def write_short(self, value):
        if type(value) is not int or not -(1 << 15) <= value < (1 << 15):
            raise ValueError("short value must fit signed 16-bit")
        self._buffer.extend((value & 0xFFFF).to_bytes(2, "big"))
        return self

    def write_int(self, value):
        if type(value) is not int or not -(1 << 31) <= value < (1 << 31):
            raise ValueError("int value must fit signed 32-bit")
        self._buffer.extend((value & 0xFFFFFFFF).to_bytes(4, "big"))
        return self

    def write_long(self, value):
        if type(value) is not int or not -(1 << 63) <= value < (1 << 63):
            raise ValueError("long value must fit signed 64-bit")
        self._buffer.extend((value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"))
        return self

    def write_string(self, value):
        if value is None:
            return self.write_char(0xFFFF)
        if not isinstance(value, str):
            raise TypeError("string value must be str or None")
        encoded = value.encode("utf-16-be", errors="surrogatepass")
        code_units = len(encoded) // 2
        if code_units >= 0x8000:
            raise ValueError("AOW string length must be below 32768 UTF-16 code units")
        self.write_char(code_units)
        self._buffer.extend(encoded)
        return self

    def to_bytes(self):
        return bytes(self._buffer)


class AowPrimitiveReader:
    def __init__(self, data):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("reader data must be bytes-like")
        self._data = memoryview(data).cast("B")
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
        value = (self._read_u16() << 16) | self._read_u16()
        return value - 0x100000000 if value & 0x80000000 else value

    def read_long(self):
        value = (self._read_u32() << 32) | self._read_u32()
        return value - 0x10000000000000000 if value & 0x8000000000000000 else value

    def read_string(self):
        code_units = self._read_u16()
        if code_units & 0x8000:
            return None
        raw = self._take(code_units * 2)
        return raw.decode("utf-16-be", errors="surrogatepass")

    def require_consumed(self):
        """Reject trailing bytes after a caller-defined primitive payload."""
        if self.remaining:
            raise ValueError("trailing bytes in primitive payload: " + str(self.remaining))
        return self
