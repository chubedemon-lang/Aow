# Synthetic session registry

The in-memory SessionRegistry is a bounded, local-only test primitive. It is
not an AOW authentication, reconnect, or session protocol implementation.

Registry-managed operations (open, authenticate, select_character,
join_map, leave_map, transfer_connection, close, and close_all) are serialized
by a re-entrant lock. This makes the capacity check and the one-active-session
constraints for accounts and characters atomic for concurrent callers within
one Python process.

For compatibility with the existing synthetic movement and handoff helpers,
open(), get(), and transfer_connection() return a Session handle. When a
Session is registry-owned, every public transition method on that handle is
routed back through the registry. This includes authenticate(), character
selection, map entry/exit, and close(). A retained handle is rebound to the new
connection key during a verified local handoff; after close, it is detached
and the closed state machine rejects further transitions.

The Session snapshot itself is a frozen point-in-time value. Call snapshot
again to observe current state. The underscore-prefixed unchecked transition
methods and handler binding are internal implementation details; callers must
use public transition methods.

A future multi-process server must enforce these constraints in the durable
database with unique indexes/transactions rather than relying on this
process-local lock.

Run:

python -m unittest discover -s tests -p 'test_synthetic_session_registry.py' -v

All identifiers and transitions here are synthetic fixtures. No wire message
IDs, reconnect semantics, account protocol, or APK compatibility are implied.
