"""Durable synthetic reward ledger. NOT an AOW APK wire protocol.

Each grant and its idempotency receipt commit in the same SQLite transaction.
This is a separate persistence prototype, not wired to InventoryLedger.
"""
import sqlite3


class RewardConflict(ValueError):
    """An idempotency key was reused for a different request."""


class SqliteRewardLedger:
    def __init__(self, connection: sqlite3.Connection):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.db.execute("""CREATE TABLE IF NOT EXISTS reward_balances (
            player_id TEXT NOT NULL, item_id TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity >= 0),
            PRIMARY KEY(player_id, item_id))""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS reward_receipts (
            request_id TEXT PRIMARY KEY, player_id TEXT NOT NULL,
            quest_id INTEGER NOT NULL, item_id TEXT NOT NULL,
            quantity INTEGER NOT NULL CHECK(quantity > 0))""")
        self.db.commit()

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
        if type(quantity) is not int or quantity <= 0:
            raise ValueError("invalid quantity")
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
            self.db.execute("""INSERT INTO reward_balances(player_id,item_id,quantity)
                VALUES(?,?,?) ON CONFLICT(player_id,item_id)
                DO UPDATE SET quantity=quantity+excluded.quantity""",
                (player_id, item_id, quantity))
            self.db.commit()
            return True
        except BaseException:
            self.db.rollback()
            raise

    def balance(self, player_id: str, item_id: str) -> int:
        row = self.db.execute(
            "SELECT quantity FROM reward_balances WHERE player_id=? AND item_id=?",
            (player_id, item_id)).fetchone()
        return row[0] if row else 0
