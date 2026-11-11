"""Regression tests for synthetic quest-award receipt replay validation."""
import os
import sqlite3
import tempfile
import unittest

from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_quest_inventory_award_store import (
    QuestInventoryAwardError,
    QuestInventoryAwardConflict,
    SqliteQuestInventoryAwardStore,
)


class SqliteQuestInventoryAwardStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "quest-awards.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(self.db.close)
        self.inventory = SqliteInventoryStore(self.db)
        self.inventory.create("hero", capacity=5, max_stack=20)
        self.awards = SqliteQuestInventoryAwardStore(self.db, self.inventory)

    def grant(self, request_id="quest-once"):
        return self.grant_for("hero", request_id)

    def grant_for(self, character_id, request_id):
        return self.awards.grant_once(
            character_id, request_id, 0, 42, "potion", 2
        )

    def tamper_result(self, request_id, raw):
        self.db.execute(
            "UPDATE quest_inventory_awards SET result_json=? WHERE request_id=?",
            (raw, request_id),
        )

    def test_award_and_exact_replay_return_original_snapshot(self):
        first = self.grant()
        self.inventory.apply("hero", "later-change", 1, [("potion", 1)])
        replay = self.grant()
        self.assertTrue(first.awarded)
        self.assertFalse(first.replayed)
        self.assertFalse(replay.awarded)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertEqual(self.inventory.get("hero").count("potion"), 3)

    def test_request_id_cannot_be_reused_for_a_different_award(self):
        self.grant()
        with self.assertRaises(QuestInventoryAwardConflict):
            self.awards.grant_once("hero", "quest-once", 0, 43, "potion", 2)

    def test_replay_rejects_duplicate_json_keys(self):
        self.grant()
        self.tamper_result(
            "quest-once",
            '{"character_id":"hero","character_id":"hero","capacity":5,'
            '"max_stack":20,"revision":1,"items":[["potion",2]]}',
        )
        with self.assertRaisesRegex(QuestInventoryAwardError, "receipt"):
            self.grant()

    def test_replay_rejects_mismatched_character(self):
        self.grant()
        self.tamper_result(
            "quest-once",
            '{"character_id":"other","capacity":5,"max_stack":20,'
            '"revision":1,"items":[["potion",2]]}',
        )
        with self.assertRaisesRegex(QuestInventoryAwardError, "receipt"):
            self.grant()

    def test_replay_rejects_result_revision_column_mismatch(self):
        self.grant()
        self.db.execute(
            "UPDATE quest_inventory_awards SET result_revision=2 WHERE request_id=?",
            ("quest-once",),
        )
        with self.assertRaisesRegex(QuestInventoryAwardError, "receipt revision"):
            self.grant()

    def test_replay_rejects_boolean_quantity_and_nonfinite_values(self):
        cases = (
            '{"character_id":"hero","capacity":5,"max_stack":20,'
            '"revision":1,"items":[["potion",true]]}',
            '{"character_id":"hero","capacity":5,"max_stack":20,'
            '"revision":1,"items":[["potion",NaN]]}',
        )
        for index, raw in enumerate(cases):
            with self.subTest(index=index):
                request_id = "bad-value-" + str(index)
                character_id = "hero-" + str(index)
                self.inventory.create(character_id, capacity=5, max_stack=20)
                self.grant_for(character_id, request_id)
                raw = raw.replace('"hero"', '"' + character_id + '"')
                self.tamper_result(request_id, raw)
                with self.assertRaises(QuestInventoryAwardError):
                    self.grant_for(character_id, request_id)

    def test_replay_rejects_noncanonical_item_order(self):
        self.grant()
        self.tamper_result(
            "quest-once",
            '{"character_id":"hero","capacity":5,"max_stack":20,'
            '"revision":1,"items":[["potion",2],["apple",1]]}',
        )
        with self.assertRaises(QuestInventoryAwardError):
            self.grant()


if __name__ == "__main__":
    unittest.main()
