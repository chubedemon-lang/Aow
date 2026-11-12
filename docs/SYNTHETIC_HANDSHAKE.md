# Synthetic handshake state machine

`server.synthetic_handshake` is a deterministic local lifecycle fixture. It
is **not** derived from the AOW APK and does not define a wire challenge,
nonce length, packet type, message ID, or authentication exchange.

The phase is intentionally exposed as a read-only property. Callers must use
`challenge()`, `acknowledge()`, and `close()`; direct assignment such as
`handshake.phase = Phase.ESTABLISHED` is rejected. This prevents accidental
state bypass in code that composes the fixture with
`server.synthetic_connection_gate.ConnectionGate`.

The nonce is accepted only as an exact `bytes` value in the fixture's local
8–32 byte test range. A mismatched acknowledgement closes the fixture and
clears the retained nonce. Successful acknowledgement also clears the nonce.

Run focused tests:

```sh
python -m unittest tests.test_synthetic_handshake tests.test_synthetic_connection_gate -v
```

These checks validate only local synthetic state transitions. They do not
establish APK handshake compatibility. The real AOW adapter remains blocked
until authorized client-side byte fixtures or runtime traces establish the
actual exchange.
