# Synthetic handshake state machine

`server.synthetic_handshake` is a deterministic local lifecycle fixture. It
is **not** derived from the AOW APK and does not define a wire challenge,
nonce length, packet type, message ID, or authentication exchange.

The phase is exposed as a read-only property on the handshake object. The
connection gate does not expose that mutable object: its `handshake` property
returns a detached, frozen `HandshakeSnapshot` containing only the current
phase and an `established` flag. The snapshot has no `challenge()`,
`acknowledge()`, or `close()` methods. Callers must perform transitions
through `ConnectionGate.challenge()`, `acknowledge()`, and `close()`.

The detached handshake snapshot is intentionally stale after a later
transition; callers obtain a fresh snapshot from the property when they need
current status. This prevents a holder of a status view from closing or
advancing only the handshake half while leaving the session half in a
contradictory state. The session property likewise returns a frozen
`SessionSnapshot` with phase and identity fields only; it does not expose
`authenticate()`, `select_player()`, or map-transition methods. Mutating
either snapshot cannot alter the gate's underlying state.

`SyntheticSession` also exposes read-only lifecycle properties and uses slots
so ordinary accidental assignment cannot skip a transition or inject
replacement state.

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
