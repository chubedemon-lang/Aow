"""Regression tests for durable synthetic player snapshots."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sqlite_player_state_store import (
    PlayerAlreadyExists,
    PlayerMutation,
    PlayerNotFound,
    PlayerOperationConflict,
    PlayerRevisionConflict,
    PlayerStoreError,
    SqlitePlayerStateStore,
)


class SqlitePlayerStateStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "players.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.store = SqlitePlayerStateStore(self.db)
        self.addCleanup(self.db.close)

    def test_create_and_read_snapshot(self):
        created = self.store.create("hero", level=4, experience=25, currency=90)
        self.assertEqual((created.level, created.experience, created.currency,
                          created.revision), (4, 25, 90, 0))
        self.assertEqual(self.store.get("hero"), created)

    def test_duplicate_character_is_rejected(self):
        self.store.create("hero")
        with self.assertRaises(PlayerAlreadyExists):
            self.store.create("hero")
        self.assertEqual(self.store.get("hero").revision, 0)

    def test_missing_character_is_rejected(self):
        with self.assertRaises(PlayerNotFound):
            self.store.get("missing")

    def test_explicit_mutation_increments_revision(self):
        self.store.create("hero", level=2, experience=40, currency=100)
        result = self.store.apply(
            "hero", "award-1", 0, level=3,
            experience_delta=60, currency_delta=-25,
        )
        self.assertIsInstance(result, PlayerMutation)
        self.assertFalse(result.replayed)
        self.assertEqual(
            (result.snapshot.level, result.snapshot.experience,
             result.snapshot.currency, result.snapshot.revision),
            (3, 100, 75, 1),
        )
        self.assertEqual(self.store.get("hero"), result.snapshot)

    def test_identical_replay_returns_original_result(self):
        self.store.create("hero", currency=100)
        first = self.store.apply("hero", "debit-1", 0, currency_delta=-20)
        second = self.store.apply("hero", "credit-2", 1, currency_delta=5)
        replay = self.store.apply("hero", "debit-1", 0, currency_delta=-20)
        self.assertFalse(first.replayed)
        self.assertFalse(second.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertEqual(self.store.get("hero").currency, 85)
        self.assertEqual(self.store.get("hero").revision, 2)

    def test_request_id_cannot_be_reused_for_another_payload(self):
        self.store.create("hero", currency=100)
        self.store.apply("hero", "same-id", 0, currency_delta=-10)
        before = self.store.get("hero")
        with self.assertRaises(PlayerOperationConflict):
            self.store.apply("hero", "same-id", 0, currency_delta=-11)
        self.assertEqual(self.store.get("hero"), before)

    def test_stale_revision_is_rejected_without_receipt(self):
        self.store.create("hero")
        self.store.apply("hero", "first", 0, experience_delta=1)
        before = self.store.get("hero")
        with self.assertRaises(PlayerRevisionConflict):
            self.store.apply("hero", "stale", 0, currency_delta=1)
        self.assertEqual(self.store.get("hero"), before)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM player_state_mutations WHERE request_id='stale'"
            ).fetchone()[0],
            0,
        )

    def test_underflow_overflow_and_empty_mutation_are_atomic(self):
        self.store.create("hero", experience=2**63 - 1, currency=0)
        before = self.store.get("hero")
        cases = [
            ("negative-currency", {"currency_delta": -1}),
            ("experience-overflow", {"experience_delta": 1}),
            ("currency-overflow", {"currency_delta": 2**31}),
            ("empty", {}),
        ]
        for request_id, kwargs in cases:
            with self.subTest(request_id=request_id), self.assertRaises(PlayerStoreError):
                self.store.apply("hero", request_id, 0, **kwargs)
            self.assertEqual(self.store.get("hero"), before)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM player_state_mutations").fetchone()[0],
            0,
        )

    def test_invalid_inputs_do_not_create_snapshot(self):
        for character_id in ("", " ", None, "x" * 129):
            with self.subTest(character_id=character_id), self.assertRaises(PlayerStoreError):
                self.store.create(character_id)
        for kwargs in (
            {"level": True}, {"level": 0}, {"experience": True},
            {"experience": -1}, {"currency": True}, {"currency": 2**31},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(PlayerStoreError):
                self.store.create("hero", **kwargs)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM player_state_snapshots").fetchone()[0],
            0,
        )

    def test_invalid_mutation_inputs_are_rejected(self):
        self.store.create("hero")
        for args in (
            ("", 0, {"currency_delta": 1}),
            ("bad", True, {"currency_delta": 1}),
            ("bad", -1, {"currency_delta": 1}),
            ("bad", 0, {"level": True}),
            ("bad", 0, {"experience_delta": True}),
            ("bad", 0, {"currency_delta": 1.5}),
        ):
            with self.subTest(args=args), self.assertRaises(PlayerStoreError):
                self.store.apply("hero", args[0], args[1], **args[2])
        self.assertEqual(self.store.get("hero").revision, 0)

    def test_snapshot_and_receipts_survive_reopen(self):
        self.store.create("hero", level=5, experience=9, currency=12)
        expected = self.store.apply("hero", "persist-1", 0, currency_delta=7)
        self.db.close()
        reopened = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(reopened.close)
        store = SqlitePlayerStateStore(reopened)
        self.assertEqual(store.get("hero"), expected.snapshot)
        replay = store.apply("hero", "persist-1", 0, currency_delta=7)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, expected.snapshot)

    def test_concurrent_same_request_has_one_mutation(self):
        self.store.create("hero", currency=100)
        barrier = threading.Barrier(8)

        def apply_once(_):
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                store = SqlitePlayerStateStore(connection)
                barrier.wait(timeout=5)
                return store.apply("hero", "concurrent", 0, currency_delta=-5)
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(apply_once, range(8)))
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertEqual(sum(result.replayed for result in results), 7)
        self.assertTrue(all(result.snapshot == results[0].snapshot for result in results))
        self.assertEqual(self.store.get("hero").currency, 95)
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_concurrent_distinct_requests_use_revision_guard(self):
        self.store.create("hero", currency=100)
        barrier = threading.Barrier(2)

        def apply_once(request_id):
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                store = SqlitePlayerStateStore(connection)
                barrier.wait(timeout=5)
                try:
                    return store.apply(
                        "hero", request_id, 0, currency_delta=-10
                    )
                except PlayerRevisionConflict:
                    return None
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(apply_once, ("left", "right")))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.store.get("hero").currency, 90)
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_constructor_does_not_commit_callers_transaction(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (1)")
        with self.assertRaises(ValueError):
            SqlitePlayerStateStore(self.db)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM caller_work").fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
