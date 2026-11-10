"""Session-authorized synthetic character creation and selection.

This local domain service bridges an authenticated synthetic account session
to one synthetic character row and its zero-balance wallet. It does not define
AOW character fields, starter inventory, map IDs, player initialization
messages, or the original APK login/character-selection protocol.
"""
from dataclasses import dataclass
import sqlite3

from server.sessions import SessionError
from server.sqlite_session_store import SqliteSessionStore


class CharacterAlreadyExists(ValueError):
    """The authenticated account already owns its one synthetic character."""


@dataclass(frozen=True)
class CharacterSnapshot:
    character_id: int
    name: str
    map_id: str
    x: int
    y: int


def _has_unique_single_column(connection, table: str, column: str) -> bool:
    for index in connection.execute(f'PRAGMA index_list("{table}")'):
        if int(index[2]) != 1:
            continue
        index_name = str(index[1]).replace('"', '""')
        quoted = '"' + index_name + '"'
        columns = [
            row[2] for row in connection.execute(
                f"PRAGMA index_info({quoted})"
            )
        ]
        if columns == [column]:
            return True
    return False


def _has_foreign_key(connection, table: str, column: str,
                      parent_table: str, parent_column: str) -> bool:
    return any(
        row[2] == parent_table and row[3] == column and row[4] == parent_column
        for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')
    )


def require_character_lifecycle_schema(connection: sqlite3.Connection) -> None:
    """Validate all required tables and ownership/one-to-one constraints first."""
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("sqlite connection required")
    try:
        connection.execute("SELECT id FROM accounts LIMIT 0")
        connection.execute(
            "SELECT id, account_id, name, map_id, x, y FROM characters LIMIT 0"
        )
        connection.execute(
            "SELECT character_id, balance FROM wallets LIMIT 0"
        )
    except sqlite3.OperationalError as exc:
        raise ValueError(
            "initialized accounts, characters and wallets schema required"
        ) from exc

    if not _has_unique_single_column(connection, "characters", "account_id"):
        raise ValueError("characters.account_id must be unique")
    if not _has_unique_single_column(connection, "wallets", "character_id"):
        raise ValueError("wallets.character_id must be unique")
    if not _has_foreign_key(
        connection, "characters", "account_id", "accounts", "id"
    ):
        raise ValueError("characters.account_id foreign key required")
    if not _has_foreign_key(
        connection, "wallets", "character_id", "characters", "id"
    ):
        raise ValueError("wallets.character_id foreign key required")


class SqliteAuthorizedCharacterService:
    """Create, list and read one synthetic character per authenticated account.

    Every operation holds BEGIN IMMEDIATE across session resolution and the
    protected account/character/wallet operation. This serializes session
    revocation with character creation and reads. No HTTP route is registered.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 default_map_id: str = "test_map",
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.default_map_id = self._validate_map_id(default_map_id)
        require_character_lifecycle_schema(connection)
        self.db = connection
        self.db.execute("PRAGMA foreign_keys = ON")
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )

    @staticmethod
    def _validate_name(name: str) -> str:
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or "\x00" in name
            or len(name) > 64
        ):
            raise ValueError("invalid character name")
        try:
            if len(name.encode("utf-8", "strict")) > 256:
                raise ValueError("invalid character name")
        except UnicodeEncodeError:
            raise ValueError("invalid character name") from None
        return name

    @staticmethod
    def _validate_map_id(map_id: str) -> str:
        if (
            not isinstance(map_id, str)
            or not 1 <= len(map_id) <= 64
            or not all(
                ch.isascii() and (ch.isalnum() or ch in "._-")
                for ch in map_id
            )
        ):
            raise ValueError("invalid synthetic map identifier")
        return map_id

    @staticmethod
    def _character(row) -> CharacterSnapshot:
        return CharacterSnapshot(
            character_id=int(row[0]),
            name=str(row[1]),
            map_id=str(row[2]),
            x=int(row[3]),
            y=int(row[4]),
        )

    def create(self, token: str, name: str) -> CharacterSnapshot:
        """Create a character and zero-balance wallet atomically for the session."""
        name = self._validate_name(name)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            account_id = self.sessions.resolve_in_transaction(token)
            account = self.db.execute(
                "SELECT 1 FROM accounts WHERE id = ?", (account_id,)
            ).fetchone()
            if account is None:
                raise SessionError("account unavailable")
            existing = self.db.execute(
                "SELECT 1 FROM characters WHERE account_id = ?", (account_id,)
            ).fetchone()
            if existing is not None:
                raise CharacterAlreadyExists(
                    "character already exists for this account"
                )

            cursor = self.db.execute(
                """INSERT INTO characters
                   (account_id, name, map_id, x, y)
                   VALUES (?, ?, ?, 0, 0)""",
                (account_id, name, self.default_map_id),
            )
            character_id = int(cursor.lastrowid)
            self.db.execute(
                "INSERT INTO wallets(character_id, balance) VALUES (?, 0)",
                (character_id,),
            )
            row = self.db.execute(
                "SELECT id, name, map_id, x, y FROM characters WHERE id = ?",
                (character_id,),
            ).fetchone()
            snapshot = self._character(row)
            self.db.commit()
            return snapshot
        except sqlite3.IntegrityError as exc:
            self.db.rollback()
            try:
                account_id = self.sessions.resolve(token)
            except SessionError:
                raise
            if self.db.execute(
                "SELECT 1 FROM characters WHERE account_id = ?", (account_id,)
            ).fetchone() is not None:
                raise CharacterAlreadyExists(
                    "character already exists for this account"
                ) from exc
            raise
        except BaseException:
            self.db.rollback()
            raise

    def list_for_account(self, token: str) -> tuple[CharacterSnapshot, ...]:
        """List only characters belonging to the authenticated session account."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            account_id = self.sessions.resolve_in_transaction(token)
            rows = self.db.execute(
                """SELECT id, name, map_id, x, y FROM characters
                   WHERE account_id = ? ORDER BY id""",
                (account_id,),
            ).fetchall()
            result = tuple(self._character(row) for row in rows)
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise

    def get(self, token: str, character_id: int) -> CharacterSnapshot:
        """Read one owned character; unknown and foreign IDs share one error."""
        if type(character_id) is not int or not 1 <= character_id <= 2**63 - 1:
            raise SessionError("invalid character")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            account_id = self.sessions.resolve_in_transaction(token)
            row = self.db.execute(
                """SELECT id, name, map_id, x, y FROM characters
                   WHERE id = ? AND account_id = ?""",
                (character_id, account_id),
            ).fetchone()
            if row is None:
                raise SessionError("character not owned by session")
            result = self._character(row)
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise
