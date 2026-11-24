# Synthetic session phase gate

`server.synthetic_session_phases` is a transport-neutral lifecycle fixture.
It is **not** derived from AOW APK traffic and does not define a wire
handshake, authentication method, packet, message ID, or session contract.

The phase and synthetic player identifier are exposed as read-only
properties. Transitions must use `negotiate()`, `authenticate()`,
`enter_world()`, `leave_world()`, and `close()`. The instance uses slots
so accidental public assignment or attribute injection cannot bypass the
transition methods. As with other Python objects, underscore-prefixed fields
are implementation details, not a security boundary against deliberate
introspection.

`authenticate()` accepts only an exact positive integer player identifier
and requires the caller to pass `verified=True` after independently
performing verification. This fixture does not verify credentials itself and
does not accept passwords, tokens, or other secrets. Closing clears the
synthetic identity and is terminal.

Run:

```sh
python -m unittest tests.test_synthetic_session_phases -v
```

These tests validate only local state-machine invariants. They do not establish
AOW handshake, login, session, or APK compatibility. The real adapter remains
disabled until authorized unchanged-client runtime evidence is independently
reproduced.
