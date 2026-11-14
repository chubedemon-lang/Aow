# Synthetic handshake state machine

`server.synthetic_handshake` is a deterministic local lifecycle fixture. It
is **not** derived from the AOW APK and does not define a wire challenge,
nonce length, packet type, message ID, or authentication exchange.

The phase is intentionally exposed as a read-only property. Callers must use
`challenge()`, `acknowledge()`, and `close()`; direct assignment such as
`handshake.phase = Phase.ESTABLISHED` is rejected. This prevents accidental
state bypass in code that composes the fixture with
`server.synthetic_connection_gate.ConnectionGate`.

The connection gate now keeps its mutable session and handshake references in
private slots. Its `handshake` property returns the validated handshake
transition object but cannot be replaced. Its `session` property returns a
frozen `SessionSnapshot` with phase and identity fields only; the snapshot
does not expose `authenticate()`, `select_player()`, or map-transition
methods. Mutating the snapshot cannot alter the gate's underlying session.
`SyntheticSession` also exposes read-only lifecycle properties and uses slots
so accidental assignment cannot skip a transition or inject replacement
state.

The nonce is accepted only as an exact `bytes` value in the fixture's local
8–32 byte test range. A mismatched acknowledgement closes the fixture and
clears the retained nonce. Successful acknowledgement also clears the nonce.

Run focused tests:

```sh
python -m unittest tests.test_synthetic_handshake tests.test_synthetic_connection_gate tests.test_synthetic_session -v
```

These checks validate only local synthetic state transitions and in-process
API encapsulation. They do not establish APK handshake compatibility. The real
AOW adapter remains blocked until authorized client-side byte fixtures or
runtime traces establish the actual exchange.
