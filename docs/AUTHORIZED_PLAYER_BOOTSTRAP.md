# Authorized synthetic player bootstrap snapshot

## Scope

\`server/sqlite_authorized_player_bootstrap_service.py\` combines the existing character, player-state, map-position and inventory stores into one session-authorized read model.

This is a local synthetic domain service only. It is **not** an AOW login response, player-initialization packet, map-join message, inventory schema, or proof of APK compatibility. Item IDs, capacity, stack limits, map identifiers and player defaults remain synthetic.

## Consistency and authorization

\`SqliteAuthorizedPlayerBootstrapService.get_snapshot(token, character_id)\`:

1. Starts one \`BEGIN IMMEDIATE\` transaction.
2. Resolves the durable synthetic session and verifies character ownership in that transaction.
3. Reads the character row, player snapshot, map-position snapshot and inventory snapshot using the same SQLite connection.
4. Commits the read transaction and returns one immutable aggregate.

Holding the authorization transaction across all reads prevents session revocation or another protected SQLite mutation from interleaving halfway through the snapshot. The method performs no per-character inserts, updates, repairs or receipt creation.

The constructor initializes missing auxiliary store tables, consistent with the existing domain-service constructors. It does not create missing character/player/map/inventory rows. If a component is absent, the read fails closed with that store's not-found error.

## Example

\`\`\`python
import sqlite3
from server.sqlite_authorized_player_bootstrap_service import (
    SqliteAuthorizedPlayerBootstrapService,
)

db = sqlite3.connect("./var/aow_synthetic.sqlite3", isolation_level=None)
service = SqliteAuthorizedPlayerBootstrapService(db)
snapshot = service.get_snapshot(server_issued_token, character_id)
\`\`\`

The token must have been issued only after a trusted authentication step. This module does not authenticate credentials and is not exposed as an HTTP route.

## Validation

\`\`\`sh
python -m unittest discover -s tests -p 'test_sqlite_authorized_player_bootstrap_service.py' -v
python -m unittest discover -s tests -p 'test_*.py' -v
\`\`\`

Tests cover the coherent aggregate, read-only behavior, missing inventory, foreign/unknown character indistinguishability, expiry/revocation and serialization of revocation against the complete read.

## Compatibility boundary

No AOW wire field order, message ID, framing, handshake, player initialization semantics, item catalog, map ID, coordinate system or gameplay rule is inferred here. Do not connect this service to the original APK until the client-facing protocol is independently verified and reproduced with authorized, redacted wire fixtures.
