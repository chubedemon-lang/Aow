# Synthetic session registry

The in-memory SessionRegistry is a bounded, local-only test primitive. It is
not an AOW authentication, reconnect, or session protocol implementation.

Registry-managed operations (open, authenticate, select_character,
join_map, leave_map, transfer_connection, close, and close_all) are serialized
by a re-entrant lock. This makes the capacity check and the one-active-session
constraints for accounts and characters atomic for concurrent callers within
one Python process.

For composite local state updates, `locked_session(connection_id)` holds the
registry lock while yielding the current Session handle. The handle must not be
retained after the context exits. This lets a caller such as MapOccupancy
publish a related membership record before a verified connection transfer can
change the registry key.

The registry keeps a reverse lookup from each live Session object to its
current local connection key. A verified handoff updates both directions
atomically. Consumers that index related local state by stable Session identity
can therefore preserve that state when a connection key changes. Closing a
session removes the reverse lookup. The bulk `connection_keys_for()` lookup
resolves a set of handles under one registry snapshot.

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

Connection keys, account identifiers, and character identifiers accept exact
built-in `str` values only. String subclasses are rejected before length,
normalization, hashing, or comparison can invoke caller-defined hooks. This is
an in-process input-boundary rule for the synthetic registry, not a wire-format
or APK identity constraint.

A future multi-process server must enforce these constraints in the durable
database with unique indexes/transactions rather than relying on this
process-local lock.

Run:

    python -m unittest discover -s tests -p 'test_synthetic_session_registry.py' -v
    python -m unittest discover -s tests -p 'test_synthetic_map_occupancy_concurrency.py' -v

All identifiers and transitions here are synthetic fixtures. No wire message
IDs, reconnect semantics, account protocol, or APK compatibility are implied.
