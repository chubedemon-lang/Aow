"""Durable synthetic reward ledger. NOT an AOW APK wire protocol.

Each grant and its idempotency receipt commit in the same SQLite transaction.
This is a separate persistence prototype, not wired to InventoryLedger.
"""
import sqlite3


_MAX_SQLITE_INTEGER = 2**63 - 1


class RewardConflict(ValueError):
    """An idempotency key or stored balance violates a reward invariant."""


class SqliteRewardLedger:
    def __init__(self, connection: sqlite3.Connection):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.db.execute("""CREATE TABLE IF NOT EXISTS reward_balances (
            player_id TEXT NOT NULL, item_id TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(
                typeof(quantity) = 'integer'
                AND quantity BETWEEN 0 AND 9223372036854775807),
            PRIMARY KEY(player_id, item_id))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS reward_receipts (
            request_id TEXT PRIMARY KEY, player_id TEXT NOT NULL,
            quest_id INTEGER NOT NULL, item_id TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(
                typeof(quantity) = 'integer'
                AND quantity BETWEEN 1 AND 9223372036854775807))""")
        self.db.commit()

    @staticmethod
    def _validate_quantity(quantity: int) -> None:
        if (type(quantity) is not int
                or not 1 <= quantity <= _MAX_SQLITE_INTEGER):
            raise ValueError("invalid quantity")

    def _credit_balance_in_transaction(
        self, player_id: str, item_id: str, quantity: int
    ) -> int:
        """Add a reward without allowing SQLite INTEGER overflow or REAL coercion.

        The caller must already own the transaction containing the receipt.
        Read/validate/write is serialized by the caller's BEGIN IMMEDIATE.
        """
        if not self.db.in_transaction:
            raise ValueError("active SQLite transaction required")
        self._validate_quantity(quantity)
        row = self.db.execute(
            "SELECT quantity FROM reward_balances WHERE player_id=? AND item_id=?",
            (player_id, item_id),
        ).fetchone()
        current = 0 if row is None else row[0]
        if type(current) is not int or not 0 <= current <= _MAX_SQLITE_INTEGER:
            raise RewardConflict("stored reward balance is not a valid SQLite integer")
        if quantity > _MAX_SQLITE_INTEGER - current:
            raise RewardConflict("reward balance exceeds SQLite integer range")
        updated = current + quantity
        if row is None:
            self.db.execute(
                "INSERT INTO reward_balances(player_id,item_id,quantity) VALUES(?,?,?)",
                (player_id, item_id, updated),
            )
        else:
            self.db.execute(
                "UPDATE reward_balances SET quantity=? WHERE player_id=? AND item_id=?",
                (updated, player_id, item_id),
            )
        return updated

    def grant_once(self, request_id: str, player_id: str, quest_id: int,
                   item_id: str, quantity: int) -> bool:
        """Return True on new grant, False on identical replay.

        BEGIN IMMEDIATE serializes writers to the same SQLite database.
        The connection must be idle before this operation. Reject an active
        caller transaction before issuing BEGIN so caller-owned work is never
        accidentally committed or rolled back by this method.
        """
        if not all(type(v) is str and v.strip() for v in (request_id, player_id, item_id)):
            raise ValueError("invalid identifier")
        if type(quest_id) is not int or quest_id < 0:
            raise ValueError("invalid quest")
        self._validate_quantity(quantity)
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                "SELECT player_id, quest_id, item_id, quantity FROM reward_receipts WHERE request_id=?",
                (request_id,)).fetchone()
            request = (player_id, quest_id, item_id, quantity)
            if previous is not None:
                if tuple(previous) != request:
                    raise RewardConflict("idempotency key reused with different payload")
                self.db.commit()
                return False
            self.db.execute(
                "INSERT INTO reward_receipts VALUES (?, ?, ?, ?, ?)",
                (request_id, *request))
            self._credit_balance_in_transaction(player_id, item_id, quantity)
            self.db.commit()
            return True
        except BaseException:
            self.db.rollback()
            raise

    def balance(self, player_id: str, item_id: str) -> int:
        row = self.db.execute(
            "SELECT quantity FROM reward_balances WHERE player_id=? AND item_id=?",
            (player_id, item_id)).fetchone()
        if row is None:
            return 0
        quantity = row[0]
        if type(quantity) is not int or not 0 <= quantity <= _MAX_SQLITE_INTEGER:
            raise RewardConflict("stored reward balance is not a valid SQLite integer")
        return quantity
