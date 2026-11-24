# Synthetic connection manager lifecycle ownership

**Scope:** process-local synthetic connection/session coordination only. This
is not an AOW handshake, reconnect, transport, or APK compatibility contract.

The SyntheticConnectionManager.open() method returns a ConnectionGate so
callers can perform the fixture challenge, acknowledgement, authentication,
and player selection steps. A gate is bound to its owning manager before it is
published. When the gate closes directly, or closes fail-closed after a
handshake error, it invokes the manager's one-shot close callback after
releasing its own lock. The manager removes the connection only if that exact
gate still owns the connection key, then releases the associated player lease.

The identity check matters when a connection key is reused: a stale gate
handle cannot unregister a newer gate that now owns the same key. The callback
is consumed on the first close, making repeated close calls idempotent.

Gate state reads and transitions are serialized by a per-gate re-entrant lock.
The callback runs outside that lock to avoid lock inversion with the manager.
The manager continues to serialize connection-map and lease operations with
its own lock. These locks coordinate one Python process only; they do not
provide cross-process capacity or durable ownership.

Run the focused suite:

    python -m unittest discover -s tests -p 'test_synthetic_connection_gate.py' -v
    python -m unittest discover -s tests -p 'test_synthetic_connection_manager.py' -v

No packet bytes, message IDs, account protocol, AOW session semantics, or
unchanged-APK compatibility are implied.
