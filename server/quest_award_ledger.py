"""Synthetic quest reward ledger with a durable per-player quest/item uniqueness key.

Not derived from AOW APK packets. Call only after server-side authorization.
"""
from server.sqlite_reward_ledger import SqliteRewardLedger, RewardConflict


class QuestAwardLedger(SqliteRewardLedger):
    def __init__(self, connection):
        super().__init__(connection)
        self.db.execute("""CREATE TABLE IF NOT EXISTS quest_award_keys (
            player_id TEXT NOT NULL,
            quest_id INTEGER NOT NULL,
            item_id TEXT NOT NULL,
            request_id TEXT NOT NULL UNIQUE,
            quantity INTEGER NOT NULL CHECK(quantity > 0),
            PRIMARY KEY(player_id, quest_id, item_id))""")
        self.db.commit()

    def grant_quest_once(self, request_id, player_id, quest_id, item_id, quantity):
        """True if awarded, False for identical replay; reject conflicting grants.

        A distinct request id cannot award the same quest/item twice.
        The award key, receipt and balance update commit atomically.
        """
        if not all(type(v) is str and v.strip() for v in (request_id, player_id, item_id)):
            raise ValueError("invalid identifier")
        if type(quest_id) is not int or quest_id < 0:
            raise ValueError("invalid quest")
        if type(quantity) is not int or quantity <= 0:
            raise ValueError("invalid quantity")
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            key = self.db.execute(
                "SELECT request_id, quantity FROM quest_award_keys WHERE player_id=? AND quest_id=? AND item_id=?",
                (player_id, quest_id, item_id)).fetchone()
            if key is not None:
                if key != (request_id, quantity):
                    raise RewardConflict("quest reward already awarded")
                receipt = self.db.execute(
                    "SELECT player_id,quest_id,item_id,quantity FROM reward_receipts WHERE request_id=?",
                    (request_id,)).fetchone()
                if receipt != (player_id, quest_id, item_id, quantity):
                    raise RewardConflict("inconsistent receipt")
                if owns_transaction:
                    self.db.commit()
                return False
            receipt = self.db.execute(
                "SELECT player_id,quest_id,item_id,quantity FROM reward_receipts WHERE request_id=?",
                (request_id,)).fetchone()
            if receipt is not None:
                raise RewardConflict("request id already used")
            self.db.execute("INSERT INTO quest_award_keys VALUES (?,?,?,?,?)",
                            (player_id, quest_id, item_id, request_id, quantity))
            self.db.execute("INSERT INTO reward_receipts VALUES (?,?,?,?,?)",
                            (request_id, player_id, quest_id, item_id, quantity))
            self.db.execute("""INSERT INTO reward_balances VALUES (?,?,?)
                ON CONFLICT(player_id,item_id)
                DO UPDATE SET quantity=quantity+excluded.quantity""",
                            (player_id, item_id, quantity))
            if owns_transaction:
                self.db.commit()
            return True
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            raise
