# Synthetic session registry

The in-memory SessionRegistry is a bounded, local-only test primitive. It is
not an AOW authentication, reconnect, or session protocol implementation.

Registry-managed operations (open, authenticate, select_character,
transfer_connection, close, and close_all) are serialized by a
re-entrant lock. This makes the capacity check and the one-active-session
constraints for accounts and characters atomic for concurrent callers within
one Python process.

get() returns the mutable synthetic Session for read-only inspection.
Callers must not invoke its transition methods directly: doing so bypasses
registry uniqueness checks. The session object itself is not independently
thread-safe. A future multi-process server must enforce these constraints in
the durable database with unique indexes/transactions rather than relying on
this process-local lock.

Run:

python -m unittest discover -s tests -p 'test_synthetic_session_registry.py' -v

All identifiers and transitions here are synthetic fixtures. No wire message
IDs, reconnect semantics, account protocol, or APK compatibility are implied.
