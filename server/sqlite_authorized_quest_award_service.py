"""Session-authorized facade for the synthetic durable quest-award ledger.

This is a local persistence boundary only. It does not verify quest completion,
implement AOW quest packets, or establish original-game reward rules. The
trusted quest domain must validate completion before calling grant_quest_once.
Session tokens must only be issued after trusted account authentication.
Character ownership transfer is not supported.
"""
import sqlite3

from server.quest_award_ledger import QuestAwardLedger
from server.sessions import SessionError
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_session_store import SqliteSessionStore


_MAX_TTL_SECONDS = 31_536_000


class SqliteAuthorizedQuestAwardService:
    """Gate synthetic quest-award reads and writes by durable session ownership.

    The reward ledger remains separate from the authoritative inventory store.
    This facade prevents cross-account access but does not prove that a quest
    was completed; callers must perform that check in their trusted quest
    domain before granting a reward. No HTTP route is registered here.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        # Fail before creating session or reward tables on an uninitialized DB.
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
        """Persist one synthetic award after caller-verified quest completion.

        Identical retries return False. Reusing the request ID with another
        payload, or attempting a second award for the same character/quest/item,
        raises RewardConflict. Authorization is checked again on every retry.
        """
        owned_id = self.authorizer.require(token, character_id)
        return self._ledger.grant_quest_once(
            request_id, owned_id, quest_id, item_id, quantity
        )

    def balance(self, token: str, character_id: int, item_id: str) -> int:
        """Read the isolated synthetic reward balance for an owned character."""
        owned_id = self.authorizer.require(token, character_id)
        return self._ledger.balance(owned_id, item_id)
