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

    @staticmethod
    def _validate_identifier(value, field):
        if type(value) is not str or not value or value != value.strip():
            raise RewardConflict("invalid stored " + field)

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

    def verify_integrity(self) -> dict:
        """Audit a stable read snapshot; never repair or migrate stored data."""
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN")
        try:
            return self._verify_integrity_snapshot()
        finally:
            if self.db.in_transaction:
                self.db.rollback()

    def _verify_integrity_snapshot(self) -> dict:
        """Validate ledger invariants using streaming cursors in one snapshot.

        Every receipt contributes one positive credit, so aggregate receipt
        quantities must exactly equal each stored player/item balance. If the
        quest-award table exists, every quest key must point to a matching
        receipt. Generic reward receipts are allowed without a quest key.

        Raw rows are consumed incrementally. Only aggregate player/item totals
        are retained in Python; receipt rows and quest rows are not materialized
        with fetchall().
        """
        try:
            if any(
                tuple(row) != ("ok",)
                for row in self.db.execute("PRAGMA quick_check")
            ):
                raise RewardConflict("SQLite quick_check failed")
            if next(self.db.execute("PRAGMA foreign_key_check"), None) is not None:
                raise RewardConflict("reward ledger foreign key check failed")

            duplicate_checks = (
                (
                    "SELECT 1 FROM reward_receipts GROUP BY request_id "
                    "HAVING COUNT(*) > 1 LIMIT 1",
                    "duplicate stored reward request id",
                ),
                (
                    "SELECT 1 FROM reward_balances GROUP BY player_id, item_id "
                    "HAVING COUNT(*) > 1 LIMIT 1",
                    "duplicate stored reward balance",
                ),
            )
            for query, message in duplicate_checks:
                if self.db.execute(query).fetchone() is not None:
                    raise RewardConflict(message)

            receipt_totals = {}
            receipt_count = 0
            for (
                request_id, player_id, quest_id, item_id, quantity
            ) in self.db.execute(
                """SELECT request_id, player_id, quest_id, item_id, quantity
                   FROM reward_receipts ORDER BY request_id"""
            ):
                self._validate_identifier(request_id, "reward request id")
                self._validate_identifier(player_id, "reward player id")
                self._validate_identifier(item_id, "reward item id")
                if type(quest_id) is not int or not 0 <= quest_id <= _MAX_SQLITE_INTEGER:
                    raise RewardConflict("invalid stored reward quest id")
                if type(quantity) is not int or not 1 <= quantity <= _MAX_SQLITE_INTEGER:
                    raise RewardConflict("invalid stored reward receipt quantity")
                key = (player_id, item_id)
                total = receipt_totals.get(key, 0) + quantity
                if total > _MAX_SQLITE_INTEGER:
                    raise RewardConflict("stored reward receipts exceed SQLite integer range")
                receipt_totals[key] = total
                receipt_count += 1

            balance_count = 0
            for player_id, item_id, quantity in self.db.execute(
                """SELECT player_id, item_id, quantity
                   FROM reward_balances ORDER BY player_id, item_id"""
            ):
                self._validate_identifier(player_id, "balance player id")
                self._validate_identifier(item_id, "balance item id")
                if type(quantity) is not int or not 0 <= quantity <= _MAX_SQLITE_INTEGER:
                    raise RewardConflict("stored reward balance is not a valid SQLite integer")
                key = (player_id, item_id)
                expected = receipt_totals.pop(key, None)
                if expected is None or expected != quantity:
                    raise RewardConflict("reward balances do not match durable receipt totals")
                balance_count += 1
            if receipt_totals:
                raise RewardConflict("reward balances do not match durable receipt totals")

            quest_key_count = 0
            quest_table = self.db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='quest_award_keys'"
            ).fetchone()
            if quest_table is not None:
                quest_duplicate_checks = (
                    (
                        "SELECT 1 FROM quest_award_keys "
                        "GROUP BY player_id, quest_id, item_id "
                        "HAVING COUNT(*) > 1 LIMIT 1"
                    ),
                    (
                        "SELECT 1 FROM quest_award_keys GROUP BY request_id "
                        "HAVING COUNT(*) > 1 LIMIT 1"
                    ),
                )
                if any(
                    self.db.execute(query).fetchone() is not None
                    for query in quest_duplicate_checks
                ):
                    raise RewardConflict("duplicate stored quest-award key")

                quest_rows = self.db.execute(
                    """SELECT q.player_id, q.quest_id, q.item_id, q.request_id,
                              q.quantity, r.request_id, r.player_id, r.quest_id,
                              r.item_id, r.quantity
                       FROM quest_award_keys AS q
                       LEFT JOIN reward_receipts AS r ON r.request_id = q.request_id
                       ORDER BY q.player_id, q.quest_id, q.item_id"""
                )
                for (
                    player_id, quest_id, item_id, request_id, quantity,
                    receipt_request_id, receipt_player_id, receipt_quest_id,
                    receipt_item_id, receipt_quantity,
                ) in quest_rows:
                    self._validate_identifier(player_id, "quest-award player id")
                    self._validate_identifier(item_id, "quest-award item id")
                    self._validate_identifier(request_id, "quest-award request id")
                    if (type(quest_id) is not int
                            or not 0 <= quest_id <= _MAX_SQLITE_INTEGER):
                        raise RewardConflict("invalid stored quest-award quest id")
                    if type(quantity) is not int or not 1 <= quantity <= _MAX_SQLITE_INTEGER:
                        raise RewardConflict("invalid stored quest-award quantity")
                    expected = (player_id, quest_id, item_id, quantity)
                    actual = (
                        receipt_player_id, receipt_quest_id,
                        receipt_item_id, receipt_quantity,
                    )
                    if receipt_request_id != request_id or actual != expected:
                        raise RewardConflict(
                            "quest-award key does not match its reward receipt"
                        )
                    quest_key_count += 1

            return {
                "balances": balance_count,
                "receipts": receipt_count,
                "quest_award_keys": quest_key_count,
            }
        except sqlite3.DatabaseError as exc:
            raise RewardConflict(
                "reward ledger integrity check could not complete"
            ) from exc
