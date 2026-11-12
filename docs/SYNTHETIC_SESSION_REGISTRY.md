# Synthetic session registry

The in-memory SessionRegistry is a bounded, local-only test primitive. It is
not an AOW authentication, reconnect, or session protocol implementation.

Registry-managed operations (open, authenticate, select_character,
transfer_connection, close, and close_all) are serialized by a
re-entrant lock. This makes the capacity check and the one-active-session
constraints for accounts and characters atomic for concurrent callers within
one Python process.

The registry never returns its mutable Session instances. open(), get(), and
transfer_connection() return frozen, point-in-time Snapshot values instead.
Callers must use registry methods for state transitions, so an object returned
for inspection cannot bypass account/character uniqueness checks. A snapshot
does not update after later transitions; call get() again for current state.

A future multi-process server must enforce these constraints in the durable
database with unique indexes/transactions rather than relying on this
process-local lock.

Run:

python -m unittest discover -s tests -p 'test_synthetic_session_registry.py' -v

All identifiers and transitions here are synthetic fixtures. No wire message
IDs, reconnect semantics, account protocol, or APK compatibility are implied.
