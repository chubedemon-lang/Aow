"""Session ownership tests for synthetic durable shop purchases only."""
import os
import sqlite3
import threading
import tempfile
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_shop_service import SqliteAuthorizedShopService
from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_player_state_store import SqlitePlayerStateStore
from server.sqlite_shop_store import ShopOffer, ShopPurchase

from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedShopServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-shop.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        self.addCleanup(self.db.close)
        self.db.execute(
            """CREATE TABLE characters (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL
            )"""
        )
        self.db.executemany(
            "INSERT INTO characters(id, account_id) VALUES (?, ?)",
            ((101, 1), (202, 2)),
        )
        self.db.commit()
        self.now = [3000.0]
        self.offers = {
            "potion-pack": ShopOffer("potion-pack", "potion", 12),
            "rare-token": ShopOffer("rare-token", "token", 40),
        }
        self.service = SqliteAuthorizedShopService(
            self.db, self.offers, max_purchase_quantity=5,
            ttl_seconds=30, clock=lambda: self.now[0],
        )
        self.players = SqlitePlayerStateStore(self.db)
        self.inventory = SqliteInventoryStore(self.db)
        self.players.create("101", level=3, experience=17, currency=100)
        self.inventory.create("101", capacity=3, max_stack=10)
        self.players.create("202", currency=50)
        self.inventory.create("202", capacity=3, max_stack=10)
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_purchase_and_both_snapshots_advance(self):
        result = self.service.purchase(
            self.owner_token, 101, "buy-1", 0, 0, "potion-pack", 2
        )
        self.assertIsInstance(result, ShopPurchase)
        self.assertFalse(result.replayed)
        self.assertEqual(result.total, 24)
        self.assertEqual(result.player.currency, 76)
        self.assertEqual(result.player.revision, 1)
        self.assertEqual(result.inventory.count("potion"), 2)
        self.assertEqual(result.inventory.revision, 1)
        self.assertEqual(self.players.get("101"), result.player)
        self.assertEqual(self.inventory.get("101"), result.inventory)

    def test_foreign_account_cannot_purchase_for_owned_character(self):
        with self.assertRaises(SessionError):
            self.service.purchase(
                self.other_token, 101, "foreign-buy", 0, 0, "potion-pack", 1
            )
        self.assertEqual(self.players.get("101").currency, 100)
        self.assertEqual(self.inventory.get("101").items, ())
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM shop_purchase_receipts"
            ).fetchone()[0],
            0,
        )

    def test_unknown_and_foreign_character_have_same_authorization_error(self):
        messages = []
        for character_id in (202, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.purchase(
                    self.owner_token, character_id,
                    "hidden-" + str(character_id), 0, 0, "potion-pack", 1,
                )
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM shop_purchase_receipts"
            ).fetchone()[0],
            0,
        )

    def test_expired_session_cannot_purchase(self):
        self.now[0] = 3030.0
        with self.assertRaises(SessionError):
            self.service.purchase(
                self.owner_token, 101, "expired-buy", 0, 0, "potion-pack", 1
            )
        self.assertEqual(self.players.get("101").currency, 100)
        self.assertEqual(self.inventory.get("101").items, ())
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM shop_purchase_receipts"
            ).fetchone()[0],
            0,
        )

    def test_revoked_session_cannot_purchase(self):
        self.assertTrue(self.service.sessions.revoke(self.owner_token))
        with self.assertRaises(SessionError):
            self.service.purchase(
                self.owner_token, 101, "revoked-buy", 0, 0, "potion-pack", 1
            )
        self.assertEqual(self.players.get("101").currency, 100)
        self.assertEqual(self.inventory.get("101").items, ())

    def test_idempotent_replay_is_authorized_again(self):
        first = self.service.purchase(
            self.owner_token, 101, "stable-buy", 0, 0, "potion-pack", 1
        )
        self.service.purchase(
            self.owner_token, 101, "later-buy", 1, 1, "potion-pack", 1
        )
        replay = self.service.purchase(
            self.owner_token, 101, "stable-buy", 0, 0, "potion-pack", 1
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.player, first.player)
        self.assertEqual(replay.inventory, first.inventory)
        with self.assertRaises(SessionError):
            self.service.purchase(
                self.other_token, 101, "stable-buy", 0, 0, "potion-pack", 1
            )
        self.assertEqual(self.players.get("101").currency, 76)
        self.assertEqual(self.inventory.get("101").count("potion"), 2)

    def test_invalid_character_ids_fail_closed(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.purchase(
                    self.owner_token, value, "invalid-char", 0, 0,
                    "potion-pack", 1,
                )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM shop_purchase_receipts"
            ).fetchone()[0],
            0,
        )

    def test_missing_ownership_schema_has_no_database_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedShopService(
                db, {"potion-pack": self.offers["potion-pack"]}
            )
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertNotIn("durable_sessions", tables)
        self.assertNotIn("shop_purchase_receipts", tables)
        self.assertNotIn("player_state_snapshots", tables)
        self.assertNotIn("inventory_snapshots", tables)



    def test_session_revocation_serializes_with_atomic_purchase(self):
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_purchase = self.service._shop.purchase

        def paused_purchase(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release shop purchase")
            return original_purchase(*args, **kwargs)

        self.service._shop.purchase = paused_purchase

        def purchase():
            try:
                outcome["purchase"] = self.service.purchase(
                    self.owner_token, 101, "atomic-revoke-buy",
                    0, 0, "potion-pack", 1,
                )
            except BaseException as exc:
                outcome["purchase_error"] = exc

        def revoke():
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                sessions = SqliteSessionStore(
                    connection, ttl_seconds=30, clock=lambda: self.now[0]
                )
                revoke_started.set()
                outcome["revoked"] = sessions.revoke(self.owner_token)
            except BaseException as exc:
                outcome["revoke_error"] = exc
            finally:
                connection.close()
                revoke_done.set()

        purchase_thread = threading.Thread(target=purchase)
        revoke_thread = threading.Thread(target=revoke)
        purchase_thread.start()
        self.assertTrue(entered.wait(5))
        revoke_thread.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(
                revoke_done.wait(0.2),
                "session revocation must wait for the authorized purchase",
            )
        finally:
            release.set()
        purchase_thread.join(5)
        revoke_thread.join(5)
        self.assertFalse(purchase_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self.assertNotIn("purchase_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertTrue(outcome["revoked"])
        self.assertEqual(outcome["purchase"].total, 12)
        self.assertEqual(self.players.get("101").currency, 88)
        self.assertEqual(self.inventory.get("101").count("potion"), 1)
        with self.assertRaises(SessionError):
            self.service.purchase(
                self.owner_token, 101, "after-revoke",
                1, 1, "potion-pack", 1,
            )


if __name__ == "__main__":
    unittest.main()
