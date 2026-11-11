"""Regression tests for atomic durable synthetic shop purchases."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_player_state_store import SqlitePlayerStateStore
from server.sqlite_shop_store import (
    ShopInsufficientFunds,
    ShopOffer,
    ShopOfferNotFound,
    ShopOperationConflict,
    ShopRevisionConflict,
    ShopStoreError,
    SqliteShopStore,
)


class SqliteShopStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "shop.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(self.db.close)
        self.players = SqlitePlayerStateStore(self.db)
        self.inventory = SqliteInventoryStore(self.db)
        self.players.create("hero", level=3, experience=17, currency=100)
        self.inventory.create("hero", capacity=1, max_stack=5)
        self.offers = {
            "potion-pack": ShopOffer("potion-pack", "potion", 12),
            "rare-token": ShopOffer("rare-token", "token", 40),
        }
        self.shop = SqliteShopStore(self.db, self.offers, max_purchase_quantity=5)

    def test_purchase_debits_and_grants_in_one_revision_step(self):
        result = self.shop.purchase("hero", "buy-1", 0, 0, "potion-pack", 2)
        self.assertFalse(result.replayed)
        self.assertEqual(result.total, 24)
        self.assertEqual(result.player.currency, 76)
        self.assertEqual(result.player.revision, 1)
        self.assertEqual(result.inventory.count("potion"), 2)
        self.assertEqual(result.inventory.revision, 1)
        self.assertEqual(self.players.get("hero"), result.player)
        self.assertEqual(self.inventory.get("hero"), result.inventory)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM shop_purchase_receipts").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM player_state_mutations").fetchone()[0],
            1,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            1,
        )

    def test_insufficient_funds_changes_neither_store(self):
        self.players.apply("hero", "empty-wallet", 0, currency_delta=-95)
        before_player = self.players.get("hero")
        before_inventory = self.inventory.get("hero")
        with self.assertRaises(ShopInsufficientFunds):
            self.shop.purchase("hero", "too-expensive", 1, 0, "rare-token", 1)
        self.assertEqual(self.players.get("hero"), before_player)
        self.assertEqual(self.inventory.get("hero"), before_inventory)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM shop_purchase_receipts").fetchone()[0],
            0,
        )

    def test_stack_limit_failure_does_not_debit(self):
        self.shop.purchase("hero", "first", 0, 0, "potion-pack", 4)
        before_player = self.players.get("hero")
        before_inventory = self.inventory.get("hero")
        with self.assertRaises(ShopStoreError):
            self.shop.purchase(
                "hero", "stack-overflow", before_player.revision,
                before_inventory.revision, "potion-pack", 2,
            )
        self.assertEqual(self.players.get("hero"), before_player)
        self.assertEqual(self.inventory.get("hero"), before_inventory)

    def test_slot_limit_failure_does_not_debit(self):
        self.shop.purchase("hero", "first", 0, 0, "potion-pack", 1)
        before_player = self.players.get("hero")
        before_inventory = self.inventory.get("hero")
        with self.assertRaises(ShopStoreError):
            self.shop.purchase(
                "hero", "second-slot", before_player.revision,
                before_inventory.revision, "rare-token", 1,
            )
        self.assertEqual(self.players.get("hero"), before_player)
        self.assertEqual(self.inventory.get("hero"), before_inventory)

    def test_stale_player_or_inventory_revision_is_rejected(self):
        self.players.apply("hero", "external-player-change", 0, experience_delta=1)
        with self.assertRaises(ShopRevisionConflict):
            self.shop.purchase("hero", "stale-player", 0, 0, "potion-pack")
        self.inventory.apply("hero", "external-inventory-change", 0, [("herb", 1)])
        with self.assertRaises(ShopRevisionConflict):
            self.shop.purchase("hero", "stale-inventory", 1, 0, "potion-pack")
        self.assertEqual(self.players.get("hero").currency, 100)
        self.assertEqual(self.inventory.get("hero").count("herb"), 1)

    def test_exact_retry_returns_original_result_after_later_mutations(self):
        first = self.shop.purchase("hero", "stable-request", 0, 0, "potion-pack", 1)
        self.players.apply("hero", "later-player-change", 1, currency_delta=5)
        self.inventory.apply("hero", "later-inventory-change", 1, [("potion", 1)])
        replay = self.shop.purchase("hero", "stable-request", 0, 0, "potion-pack", 1)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.player, first.player)
        self.assertEqual(replay.inventory, first.inventory)
        self.assertEqual(self.players.get("hero").currency, 93)
        self.assertEqual(self.inventory.get("hero").count("potion"), 2)

    def test_retry_survives_offer_removal_and_repricing(self):
        original = self.shop.purchase("hero", "catalog-change", 0, 0, "potion-pack", 1)
        changed_catalog = {
            "potion-pack": ShopOffer("potion-pack", "potion", 99),
        }
        changed_shop = SqliteShopStore(self.db, changed_catalog)
        replay = changed_shop.purchase("hero", "catalog-change", 0, 0, "potion-pack", 1)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.total, original.total)
        self.assertEqual(replay.player, original.player)
        removed_catalog_shop = SqliteShopStore(
            self.db, {"rare-token": self.offers["rare-token"]}
        )
        removed_replay = removed_catalog_shop.purchase(
            "hero", "catalog-change", 0, 0, "potion-pack", 1
        )
        self.assertTrue(removed_replay.replayed)
        self.assertEqual(removed_replay, replay)

    def test_request_id_cannot_be_reused_for_another_purchase(self):
        self.shop.purchase("hero", "same-key", 0, 0, "potion-pack", 1)
        with self.assertRaises(ShopOperationConflict):
            self.shop.purchase("hero", "same-key", 0, 0, "potion-pack", 2)
        with self.assertRaises(ShopOperationConflict):
            self.shop.purchase("hero", "same-key", 0, 0, "rare-token", 1)
        self.assertEqual(self.players.get("hero").currency, 88)
        self.assertEqual(self.inventory.get("hero").count("potion"), 1)

    def test_receipt_and_replay_survive_database_reopen(self):
        expected = self.shop.purchase("hero", "persisted", 0, 0, "potion-pack", 2)
        self.db.close()
        reopened = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(reopened.close)
        shop = SqliteShopStore(reopened, self.offers)
        replay = shop.purchase("hero", "persisted", 0, 0, "potion-pack", 2)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.player, expected.player)
        self.assertEqual(replay.inventory, expected.inventory)

    def test_failure_to_write_receipt_rolls_back_debit_and_grant(self):
        self.db.execute(
            """CREATE TRIGGER reject_shop_receipt
               BEFORE INSERT ON shop_purchase_receipts
               BEGIN SELECT RAISE(ABORT, 'receipt storage unavailable'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.shop.purchase("hero", "rollback", 0, 0, "potion-pack", 2)
        self.assertEqual(self.players.get("hero").currency, 100)
        self.assertEqual(self.players.get("hero").revision, 0)
        self.assertEqual(self.inventory.get("hero").items, ())
        self.assertEqual(self.inventory.get("hero").revision, 0)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM player_state_mutations").fetchone()[0],
            0,
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            0,
        )

    def test_concurrent_identical_requests_commit_exactly_once(self):
        count = 8
        barrier = threading.Barrier(count)

        def buy_once(_):
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            try:
                shop = SqliteShopStore(connection, self.offers)
                barrier.wait(timeout=10)
                return shop.purchase("hero", "concurrent", 0, 0, "potion-pack", 2)
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=count) as pool:
            results = list(pool.map(buy_once, range(count)))
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertEqual(sum(result.replayed for result in results), count - 1)
        self.assertTrue(all(result.player == results[0].player for result in results))
        self.assertEqual(self.players.get("hero").currency, 76)
        self.assertEqual(self.inventory.get("hero").count("potion"), 2)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM shop_purchase_receipts").fetchone()[0],
            1,
        )

    def test_invalid_request_inputs_do_not_mutate_state(self):
        cases = [
            ("", 0, 0, "potion-pack", 1),
            ("bad", True, 0, "potion-pack", 1),
            ("bad", 0, -1, "potion-pack", 1),
            ("bad", 0, 0, "potion-pack", True),
            ("bad", 0, 0, "", 1),
            ("bad", 0, 0, "potion-pack", 6),
        ]
        for request_id, player_rev, inventory_rev, offer_id, quantity in cases:
            with self.subTest(request_id=request_id, quantity=quantity):
                with self.assertRaises(ShopStoreError):
                    self.shop.purchase(
                        "hero", request_id, player_rev, inventory_rev,
                        offer_id, quantity,
                    )
        with self.assertRaises(ShopOfferNotFound):
            self.shop.purchase("hero", "unknown", 0, 0, "missing")
        self.assertEqual(self.players.get("hero").currency, 100)
        self.assertEqual(self.inventory.get("hero").items, ())
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM shop_purchase_receipts").fetchone()[0],
            0,
        )

    def test_offer_and_store_configuration_are_validated(self):
        for offer in (
            ShopOffer("ok", "potion", 1),
        ):
            self.assertEqual(offer.offer_id, "ok")
        for args in (
            ("", "potion", 1),
            ("bad id", "potion", 1),
            ("ok", "bad id", 1),
            ("ok", "potion", True),
            ("ok", "potion", 0),
        ):
            with self.subTest(args=args), self.assertRaises(ShopStoreError):
                ShopOffer(*args)
        with self.assertRaises(ShopStoreError):
            SqliteShopStore(self.db, {"wrong-key": ShopOffer("right-id", "potion", 1)})
        with self.assertRaises(ShopStoreError):
            SqliteShopStore(self.db, self.offers, max_purchase_quantity=0)

    def test_player_and_inventory_are_isolated_by_character(self):
        self.players.create("other", currency=50)
        self.inventory.create("other")
        result = self.shop.purchase("other", "other-buy", 0, 0, "potion-pack", 1)
        self.assertEqual(result.player.currency, 38)
        self.assertEqual(self.players.get("hero").currency, 100)
        self.assertEqual(self.inventory.get("hero").items, ())



    def test_replay_rejects_duplicate_json_keys(self):
        self.shop.purchase("hero", "tampered-duplicate", 0, 0, "potion-pack", 1)
        self.db.execute(
            "UPDATE shop_purchase_receipts SET result_json=? WHERE request_id=?",
            ('{"character_id":"hero","character_id":"hero",'
             '"offer_id":"potion-pack","quantity":1,"total":12,'
             '"player":{"level":3,"experience":17,"currency":88,"revision":1},'
             '"inventory":{"capacity":1,"max_stack":5,"revision":1,'
             '"items":[["potion",1]]}}', "tampered-duplicate"),
        )
        with self.assertRaisesRegex(ShopStoreError, "duplicate JSON key"):
            self.shop.purchase("hero", "tampered-duplicate", 0, 0, "potion-pack", 1)

    def test_replay_rejects_receipt_for_another_character(self):
        self.shop.purchase("hero", "tampered-owner", 0, 0, "potion-pack", 1)
        self.db.execute(
            "UPDATE shop_purchase_receipts SET result_json=? WHERE request_id=?",
            ('{"character_id":"other","offer_id":"potion-pack","quantity":1,'
             '"total":12,"player":{"level":3,"experience":17,"currency":88,'
             '"revision":1},"inventory":{"capacity":1,"max_stack":5,'
             '"revision":1,"items":[["potion",1]]}}', "tampered-owner"),
        )
        with self.assertRaisesRegex(ShopStoreError, "identity or amount"):
            self.shop.purchase("hero", "tampered-owner", 0, 0, "potion-pack", 1)

    def test_replay_rejects_boolean_quantity_and_nonfinite_total(self):
        cases = (
            ('{"character_id":"hero","offer_id":"potion-pack","quantity":true,'
             '"total":12,"player":{"level":3,"experience":17,"currency":88,'
             '"revision":1},"inventory":{"capacity":1,"max_stack":5,'
             '"revision":1,"items":[["potion",1]]}}', "boolean quantity"),
            ('{"character_id":"hero","offer_id":"potion-pack","quantity":1,'
             '"total":NaN,"player":{"level":3,"experience":17,"currency":88,'
             '"revision":1},"inventory":{"capacity":1,"max_stack":5,'
             '"revision":1,"items":[["potion",1]]}}', "non-finite total"),
        )
        for index, (raw, label) in enumerate(cases):
            with self.subTest(case=label):
                request_id = "tampered-number-" + str(index)
                character_id = "hero-" + str(index)
                self.players.create(character_id, level=3, experience=17, currency=100)
                self.inventory.create(character_id, capacity=1, max_stack=5)
                self.shop.purchase(character_id, request_id, 0, 0, "potion-pack", 1)
                raw = raw.replace('"hero"', '"' + character_id + '"')
                self.db.execute(
                    "UPDATE shop_purchase_receipts SET result_json=? WHERE request_id=?",
                    (raw, request_id),
                )
                with self.assertRaises(ShopStoreError):
                    self.shop.purchase(character_id, request_id, 0, 0, "potion-pack", 1)

    def test_replay_rejects_result_revision_column_mismatch(self):
        self.shop.purchase("hero", "tampered-revision", 0, 0, "potion-pack", 1)
        self.db.execute(
            "UPDATE shop_purchase_receipts SET player_revision=2 WHERE request_id=?",
            ("tampered-revision",),
        )
        with self.assertRaisesRegex(ShopStoreError, "revision columns"):
            self.shop.purchase("hero", "tampered-revision", 0, 0, "potion-pack", 1)

    def test_replay_rejects_corrupt_nested_inventory_snapshot(self):
        self.shop.purchase("hero", "tampered-inventory", 0, 0, "potion-pack", 1)
        self.db.execute(
            "UPDATE shop_purchase_receipts SET result_json=? WHERE request_id=?",
            ('{"character_id":"hero","offer_id":"potion-pack","quantity":1,'
             '"total":12,"player":{"level":3,"experience":17,"currency":88,'
             '"revision":1},"inventory":{"capacity":1,"max_stack":5,'
             '"revision":1,"items":[["potion",true]]}}', "tampered-inventory"),
        )
        with self.assertRaisesRegex(ShopStoreError, "inventory receipt"):
            self.shop.purchase("hero", "tampered-inventory", 0, 0, "potion-pack", 1)


if __name__ == "__main__":
    unittest.main()
