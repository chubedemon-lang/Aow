# Synthetic frame codec input boundary

`server.synthetic_frame_codec` is a local test harness using a two-byte
big-endian payload length. It is **not** the AOW APK wire format and must not
be connected to the original client or described as an AOW decoder.

The encoder and decoder accept only an exact built-in immutable `bytes`
object. A `bytes` subclass can override methods such as `__len__` and run
caller code during validation. Exact-type validation rejects such objects
before a length check, iteration, or buffer mutation occurs.

The decoder leaves its existing buffered prefix unchanged when a non-canonical
input type is rejected. This differs intentionally from an oversized chunk or
invalid frame, which clears the synthetic decoder buffer to avoid continuing
from a failed synthetic stream.

Run:

```sh
python -m unittest discover -s tests -p 'test_synthetic_frame_codec.py' -v
```

These tests use fabricated bytes only. They add no evidence about AOW framing,
message IDs, handshake, login, or unchanged-APK compatibility.
