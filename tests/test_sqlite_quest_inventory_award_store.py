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


class HostileText(str):
    def __bool__(self):
        raise AssertionError("custom text truthiness hook must not run")

    def __len__(self):
        raise AssertionError("custom text length hook must not run")

    def strip(self, *args, **kwargs):
        raise AssertionError("custom text strip hook must not run")

    def encode(self, *args, **kwargs):
        raise AssertionError("custom text encode hook must not run")


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

    def test_rejects_text_subclasses_before_custom_hooks(self):
        operations = (
            lambda: self.awards.grant_once(
                "hero", HostileText("quest-request"), 0, 42, "potion", 2
            ),
            lambda: self.awards.grant_once(
                "hero", "quest-request", 0, 42, HostileText("potion"), 2
            ),
        )
        for index, operation in enumerate(operations):
            with self.subTest(identifier=index):
                with self.assertRaises(QuestInventoryAwardError):
                    operation()

        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.inventory.get("hero").items, ())
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM quest_inventory_awards"
            ).fetchone()[0],
            0,
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



    def _drop_award_table(self):
        self.db.execute("DROP TABLE quest_inventory_awards")

    def _create_award_table(self, *, request_id_type="TEXT",
                            unique_award=True):
        unique_clause = (
            ", UNIQUE(character_id, quest_id, item_id)"
            if unique_award else ""
        )
        self.db.execute(
            """CREATE TABLE quest_inventory_awards (
                request_id """ + request_id_type + """ PRIMARY KEY,
                character_id TEXT NOT NULL,
                quest_id INTEGER NOT NULL,
                item_id TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                expected_inventory_revision INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                result_revision INTEGER NOT NULL
            """ + unique_clause + ")"
        )

    def test_constructor_rejects_wrong_column_affinity_before_index_creation(self):
        self._drop_award_table()
        self._create_award_table(request_id_type="INTEGER")
        with self.assertRaisesRegex(QuestInventoryAwardError, "schema"):
            SqliteQuestInventoryAwardStore(self.db, self.inventory)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(
            self.db.execute(
                "SELECT type FROM sqlite_master "
                "WHERE name='quest_inventory_awards_character'"
            ).fetchall(),
            [],
        )
        self.assertEqual(
            self.db.execute(
                "PRAGMA table_info(quest_inventory_awards)"
            ).fetchone()[2],
            "INTEGER",
        )

    def test_constructor_rejects_missing_award_uniqueness_constraint(self):
        self._drop_award_table()
        self._create_award_table(unique_award=False)
        with self.assertRaisesRegex(QuestInventoryAwardError, "uniqueness"):
            SqliteQuestInventoryAwardStore(self.db, self.inventory)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(
            self.db.execute(
                "SELECT type FROM sqlite_master "
                "WHERE name='quest_inventory_awards_character'"
            ).fetchall(),
            [],
        )

    def test_constructor_rolls_back_table_when_named_index_belongs_elsewhere(self):
        self._drop_award_table()
        self.db.execute(
            "CREATE TABLE quest_award_index_host (other_id TEXT)"
        )
        self.db.execute(
            "CREATE INDEX quest_inventory_awards_character "
            "ON quest_award_index_host(other_id)"
        )
        with self.assertRaisesRegex(QuestInventoryAwardError, "character index"):
            SqliteQuestInventoryAwardStore(self.db, self.inventory)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(
            self.db.execute(
                "SELECT type FROM sqlite_master "
                "WHERE name='quest_inventory_awards'"
            ).fetchall(),
            [],
        )
        self.assertEqual(
            self.db.execute(
                "SELECT type, tbl_name FROM sqlite_master "
                "WHERE name='quest_inventory_awards_character'"
            ).fetchone(),
            ("index", "quest_award_index_host"),
        )

    def test_constructor_creates_missing_lookup_index_on_valid_legacy_table(self):
        self.db.execute("DROP INDEX quest_inventory_awards_character")
        reopened = SqliteQuestInventoryAwardStore(self.db, self.inventory)
        self.assertIsInstance(reopened, SqliteQuestInventoryAwardStore)
        self.assertEqual(
            self.db.execute(
                "SELECT type, tbl_name FROM sqlite_master "
                "WHERE name='quest_inventory_awards_character'"
            ).fetchone(),
            ("index", "quest_inventory_awards"),
        )
        self.assertFalse(self.db.in_transaction)

    def test_constructor_rejects_view_with_award_table_name(self):
        self._drop_award_table()
        self.db.execute(
            "CREATE VIEW quest_inventory_awards AS SELECT 1 AS request_id"
        )
        with self.assertRaisesRegex(QuestInventoryAwardError, "object"):
            SqliteQuestInventoryAwardStore(self.db, self.inventory)
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(
            self.db.execute(
                "SELECT type FROM sqlite_master "
                "WHERE name='quest_inventory_awards'"
            ).fetchone(),
            ("view",),
        )

if __name__ == "__main__":
    unittest.main()
