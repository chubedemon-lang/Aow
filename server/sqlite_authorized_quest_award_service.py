"""Session-authorized facade for the synthetic durable quest-award ledger.

This is a local persistence boundary only. It does not verify quest completion,
implement AOW quest packets, or establish original-game reward rules. The
trusted quest domain must validate completion before granting a reward.
Session tokens must only be issued after trusted account authentication.
No HTTP route is registered by this facade.

Every operation holds BEGIN IMMEDIATE across session resolution, ownership and
the reward-ledger operation so revocation cannot race a grant or balance read.
The reward ledger remains separate from authoritative inventory.

Session tokens must only be issued after trusted account authentication.
No HTTP route is registered here. Character ownership transfer is not supported.
"""
import sqlite3

from server.quest_award_ledger import QuestAwardLedger
from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_session_store import SqliteSessionStore


_MAX_TTL_SECONDS = 31_536_000


class SqliteAuthorizedQuestAwardService:
    """Gate synthetic quest-award reads and writes by durable session ownership."""

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        require_character_schema(connection)
        if (type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= _MAX_TTL_SECONDS):
            raise ValueError("invalid session ttl")

        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self._ledger = QuestAwardLedger(connection)

    def grant_quest_once(self, token: str, character_id: int,
                         request_id: str, quest_id: int,
                         item_id: str, quantity: int) -> bool:
        """Persist one synthetic award after caller-verified quest completion."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._ledger.grant_quest_once(
                request_id, owned_id, quest_id, item_id, quantity
            )

    def balance(self, token: str, character_id: int, item_id: str) -> int:
        """Read the isolated synthetic reward balance for an owned character."""
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            return self._ledger.balance(owned_id, item_id)
