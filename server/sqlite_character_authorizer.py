"""Reusable session-to-character ownership check for synthetic SQLite domains.

This module is not an AOW login or wire-protocol implementation. Session
issuance must remain behind a trusted account-authentication boundary.
"""
import sqlite3

from server.sessions import SessionError
from server.sqlite_session_store import SqliteSessionStore


def require_character_schema(connection: sqlite3.Connection) -> None:
    """Fail before any session/player/map schema is created if ownership is absent."""
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("sqlite connection required")
    try:
        connection.execute("SELECT id, account_id FROM characters LIMIT 0")
    except sqlite3.OperationalError as exc:
        raise ValueError(
            "initialized characters(id, account_id) table required"
        ) from exc


class SqliteCharacterAuthorizer:
    """Resolve a durable session and authorize an integer character ID.

    require() is a convenience check for non-transactional reads. Protected
    state operations should use require_in_transaction() inside BEGIN IMMEDIATE
    so session revocation and ownership changes serialize with the mutation.
    The current synthetic schema does not expose ownership transfer.
    """

    def __init__(self, connection: sqlite3.Connection,
                 sessions: SqliteSessionStore):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if (not isinstance(sessions, SqliteSessionStore)
                or sessions.db is not connection):
            raise ValueError("session store must use the same SQLite connection")
        self.db = connection
        self.sessions = sessions
        require_character_schema(connection)

    def require(self, token: str, character_id: int) -> str:
        """Return the domain ID after a standalone session/ownership check.

        This method is not atomic with a later state mutation. Use
        require_in_transaction() for protected writes.
        """
        if type(character_id) is not int or character_id < 1:
            raise SessionError("invalid character")
        account_id = self.sessions.resolve(token)
        row = self.db.execute(
            "SELECT 1 FROM characters WHERE id=? AND account_id=?",
            (character_id, account_id),
        ).fetchone()
        if row is None:
            # Do not reveal whether an unknown/foreign character exists.
            raise SessionError("character not owned by session")
        return str(character_id)

    def require_in_transaction(self, token: str, character_id: int) -> str:
        """Authorize a character within the caller's existing SQLite transaction.

        Callers should use BEGIN IMMEDIATE before this method and retain the
        transaction through the protected state operation.
        """
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        if type(character_id) is not int or character_id < 1:
            raise SessionError("invalid character")
        account_id = self.sessions.resolve_in_transaction(token)
        row = self.db.execute(
            "SELECT 1 FROM characters WHERE id=? AND account_id=?",
            (character_id, account_id),
        ).fetchone()
        if row is None:
            raise SessionError("character not owned by session")
        return str(character_id)
