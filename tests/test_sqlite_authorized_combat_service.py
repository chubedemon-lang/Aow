"""Ownership, persistence and replay tests for synthetic durable combat."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.combat import Battle, Fighter
from server.sessions import SessionError
from server.sqlite_authorized_combat_service import (
    CombatAlreadyExists,
    CombatNotFound,
    CombatOperationConflict,
    CombatRevisionConflict,
    CombatStoreError,
    SqliteAuthorizedCombatService,
)


class SqliteAuthorizedCombatServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "combat.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.execute(
            """CREATE TABLE characters (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL
            )"""
        )
        self.db.executemany(
            "INSERT INTO characters(id, account_id) VALUES (?, ?)",
            ((101, 1), (202, 2), (303, 1)),
        )
        self.db.commit()
        self.now = [5000.0]
        self.service = SqliteAuthorizedCombatService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    @staticmethod
    def battle():
        return Battle(
            Fighter(101, 20, 7, 2),
            Fighter(9001, 10, 3, 4),
            101,
        )

    def create_battle(self, battle_id="battle-1"):
        return self.service.create(
            self.owner_token, 101, battle_id, self.battle()
        )

    def test_create_and_read_owned_battle(self):
        created = self.create_battle()
        loaded = self.service.get(self.owner_token, 101, "battle-1")
        self.assertEqual(created, loaded)
        self.assertEqual(loaded.revision, 0)
        self.assertEqual(loaded.battle.first.hp, 20)

    def test_duplicate_battle_id_is_rejected(self):
        self.create_battle()
        with self.assertRaises(CombatAlreadyExists):
            self.create_battle()

    def test_character_must_be_a_battle_participant(self):
        battle = Battle(Fighter(9002, 20, 7, 2), Fighter(9001, 10, 3, 4), 9002)
        with self.assertRaises(SessionError):
            self.service.create(self.owner_token, 101, "not-owned", battle)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM combat_battles").fetchone()[0],
            0,
        )

    def test_new_battle_must_start_with_living_fighters(self):
        battle = Battle(
            Fighter(101, 0, 7, 2),
            Fighter(9001, 10, 3, 4),
            9001,
            turn=1,
        )
        with self.assertRaises(CombatStoreError):
            self.service.create(self.owner_token, 101, "finished", battle)

    def test_foreign_or_other_owned_character_cannot_read_battle(self):
        self.create_battle()
        with self.assertRaises(SessionError):
            self.service.get(self.other_token, 101, "battle-1")
        with self.assertRaises(SessionError):
            self.service.get(self.owner_token, 303, "battle-1")
        with self.assertRaises(CombatNotFound):
            self.service.get(self.owner_token, 101, "missing")

    def test_turn_transition_is_persisted(self):
        self.create_battle()
        first = self.service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        self.assertFalse(first.replayed)
        self.assertEqual(
            (first.event.damage, first.event.target_hp, first.snapshot.revision),
            (3, 7, 1),
        )
        second = self.service.attack(
            self.owner_token, 101, "battle-1", "turn-2", 1, 9001
        )
        self.assertEqual(
            (second.event.damage, second.event.target_hp, second.snapshot.revision),
            (1, 19, 2),
        )
        self.assertEqual(
            self.service.get(self.owner_token, 101, "battle-1"),
            second.snapshot,
        )

    def test_exact_retry_returns_original_result_after_later_turn(self):
        self.create_battle()
        first = self.service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        self.service.attack(
            self.owner_token, 101, "battle-1", "turn-2", 1, 9001
        )
        replay = self.service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertEqual(replay.event, first.event)
        self.assertEqual(
            self.service.get(self.owner_token, 101, "battle-1").revision, 2
        )

    def test_request_id_cannot_be_reused_for_another_action(self):
        self.create_battle()
        self.service.attack(
            self.owner_token, 101, "battle-1", "same-id", 0, 101
        )
        with self.assertRaises(CombatOperationConflict):
            self.service.attack(
                self.owner_token, 101, "battle-1", "same-id", 0, 9001
            )
        self.assertEqual(
            self.service.get(self.owner_token, 101, "battle-1").revision, 1
        )

    def test_stale_revision_and_wrong_turn_do_not_mutate(self):
        self.create_battle()
        self.service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        before = self.service.get(self.owner_token, 101, "battle-1")
        with self.assertRaises(CombatRevisionConflict):
            self.service.attack(
                self.owner_token, 101, "battle-1", "stale", 0, 9001
            )
        with self.assertRaises(ValueError):
            self.service.attack(
                self.owner_token, 101, "battle-1", "wrong-turn", 1, 101
            )
        self.assertEqual(
            self.service.get(self.owner_token, 101, "battle-1"), before
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM combat_mutations "
                "WHERE request_id IN ('stale', 'wrong-turn')"
            ).fetchone()[0],
            0,
        )

    def test_finished_battle_rejects_more_actions(self):
        battle = Battle(
            Fighter(101, 1, 10, 0),
            Fighter(9001, 1, 0, 0),
            101,
        )
        self.service.create(self.owner_token, 101, "terminal", battle)
        result = self.service.attack(
            self.owner_token, 101, "terminal", "finish", 0, 101
        )
        self.assertEqual(result.event.winner_id, 101)
        before = self.service.get(self.owner_token, 101, "terminal")
        with self.assertRaises(ValueError):
            self.service.attack(
                self.owner_token, 101, "terminal", "after-finish", 1, 101
            )
        self.assertEqual(
            self.service.get(self.owner_token, 101, "terminal"), before
        )

    def test_expired_and_revoked_sessions_cannot_replay_or_mutate(self):
        self.create_battle()
        self.service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        self.now[0] = 5030.0
        with self.assertRaises(SessionError):
            self.service.attack(
                self.owner_token, 101, "battle-1", "turn-1", 0, 101
            )
        with self.assertRaises(SessionError):
            self.service.get(self.owner_token, 101, "battle-1")

        fresh = self.service.sessions.issue(1)
        self.assertTrue(self.service.sessions.revoke(fresh))
        with self.assertRaises(SessionError):
            self.service.attack(fresh, 101, "battle-1", "turn-2", 1, 9001)

    def test_snapshot_and_receipts_survive_reopen(self):
        self.create_battle()
        expected = self.service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        self.db.close()
        reopened = sqlite3.connect(
            self.path, timeout=10, isolation_level=None
        )
        self.addCleanup(reopened.close)
        service = SqliteAuthorizedCombatService(
            reopened, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.assertEqual(
            service.get(self.owner_token, 101, "battle-1"),
            expected.snapshot,
        )
        replay = service.attack(
            self.owner_token, 101, "battle-1", "turn-1", 0, 101
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, expected.snapshot)

    def test_concurrent_duplicate_action_commits_once(self):
        self.create_battle()
        barrier = threading.Barrier(8)

        def apply_once(_):
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                service = SqliteAuthorizedCombatService(
                    connection, ttl_seconds=30, clock=lambda: self.now[0]
                )
                barrier.wait(timeout=5)
                return service.attack(
                    self.owner_token, 101, "battle-1", "concurrent", 0, 101
                )
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(apply_once, range(8)))
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertEqual(sum(result.replayed for result in results), 7)
        self.assertTrue(
            all(result.snapshot == results[0].snapshot for result in results)
        )
        self.assertEqual(
            self.service.get(self.owner_token, 101, "battle-1").revision, 1
        )
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM combat_mutations").fetchone()[0],
            1,
        )

    def test_invalid_identifiers_and_constructor_schema_fail_closed(self):
        for value in ("", " ", "../battle", "x" * 129, None):
            with self.subTest(value=value), self.assertRaises(CombatStoreError):
                self.service.create(self.owner_token, 101, value, self.battle())
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.create(self.owner_token, value, "invalid", self.battle())

        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedCombatService(db)
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertNotIn("durable_sessions", tables)
        self.assertNotIn("combat_battles", tables)
        self.assertNotIn("combat_mutations", tables)


if __name__ == "__main__":
    unittest.main()
