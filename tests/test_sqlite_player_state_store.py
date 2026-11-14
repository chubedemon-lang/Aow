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

    def test_verify_integrity_accepts_initial_and_mutated_snapshots(self):
        self.store.create("hero", level=4, experience=20, currency=100)
        self.store.create("other", level=2, experience=7, currency=3)
        self.store.apply(
            "hero", "audit-first", 0, level=5,
            experience_delta=10, currency_delta=-10,
        )
        self.store.apply(
            "hero", "audit-second", 1,
            experience_delta=4, currency_delta=5,
        )
        self.assertEqual(
            self.store.verify_integrity(),
            {
                "snapshots": 2,
                "mutations": 2,
                "anchored_snapshots": 2,
                "legacy_unanchored_snapshots": 0,
            },
        )

    def test_verify_integrity_rejects_missing_first_receipt(self):
        self.store.create("hero", currency=100)
        self.store.apply("hero", "audit-first", 0, currency_delta=-10)
        self.store.apply("hero", "audit-second", 1, currency_delta=5)
        self.db.execute(
            "DELETE FROM player_state_mutations WHERE request_id='audit-first'"
        )
        with self.assertRaisesRegex(PlayerStoreError, "history has a gap"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_tampered_intermediate_receipt(self):
        self.store.create("hero", currency=100)
        self.store.apply("hero", "audit-first", 0, currency_delta=-10)
        self.store.apply("hero", "audit-second", 1, currency_delta=5)
        self.db.execute(
            "UPDATE player_state_mutations SET result_currency=91 "
            "WHERE request_id='audit-first'"
        )
        with self.assertRaisesRegex(PlayerStoreError, "receipt does not match"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_orphan_mutation(self):
        self.db.execute(
            """INSERT INTO player_state_mutations
               (request_id, character_id, expected_revision, requested_level,
                experience_delta, currency_delta, result_level,
                result_experience, result_currency, result_revision)
               VALUES ('orphan', 'missing', 0, NULL, 1, 0, 1, 1, 0, 1)"""
        )
        with self.assertRaisesRegex(PlayerStoreError, "no player snapshot"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_revision_without_receipt(self):
        self.store.create("hero")
        self.db.execute(
            "UPDATE player_state_snapshots SET revision=1 WHERE character_id='hero'"
        )
        with self.assertRaisesRegex(PlayerStoreError, "no mutation history"):
            self.store.verify_integrity()


    def test_verify_integrity_rejects_missing_creation_receipt(self):
        self.store.create("hero", currency=100)
        self.db.execute(
            "DELETE FROM player_state_creations WHERE character_id='hero'"
        )
        with self.assertRaisesRegex(PlayerStoreError, "creation receipt is missing"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_tampered_creation_baseline(self):
        self.store.create("hero", currency=100)
        self.store.apply("hero", "baseline-first", 0, currency_delta=-10)
        self.db.execute(
            "UPDATE player_state_creations SET currency=99 "
            "WHERE character_id='hero'"
        )
        with self.assertRaisesRegex(
            PlayerStoreError, "receipt does not match history"
        ):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_creation_receipt_without_snapshot(self):
        self.db.execute(
            """INSERT INTO player_state_creations
               (character_id, level, experience, currency)
               VALUES ('missing', 1, 0, 0)"""
        )
        with self.assertRaisesRegex(
            PlayerStoreError, "creation receipt has no player snapshot"
        ):
            self.store.verify_integrity()

    def test_create_and_creation_receipt_are_atomic(self):
        self.db.execute(
            """CREATE TRIGGER reject_player_creation_receipt
               BEFORE INSERT ON player_state_creations
               BEGIN SELECT RAISE(ABORT, 'blocked'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create("hero", currency=50)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM player_state_snapshots WHERE character_id='hero'"
            ).fetchone()[0],
            0,
        )

    def test_legacy_schema_migrates_as_unanchored(self):
        legacy_path = os.path.join(self.temp.name, "legacy.sqlite3")
        legacy = sqlite3.connect(legacy_path, isolation_level=None)
        legacy.execute(
            """CREATE TABLE player_state_snapshots (
                character_id TEXT PRIMARY KEY,
                level INTEGER NOT NULL,
                experience INTEGER NOT NULL,
                currency INTEGER NOT NULL,
                revision INTEGER NOT NULL
            )"""
        )
        legacy.execute(
            """CREATE TABLE player_state_mutations (
                request_id TEXT PRIMARY KEY,
                character_id TEXT NOT NULL,
                expected_revision INTEGER NOT NULL,
                requested_level INTEGER,
                experience_delta INTEGER NOT NULL,
                currency_delta INTEGER NOT NULL,
                result_level INTEGER NOT NULL,
                result_experience INTEGER NOT NULL,
                result_currency INTEGER NOT NULL,
                result_revision INTEGER NOT NULL
            )"""
        )
        legacy.execute(
            "INSERT INTO player_state_snapshots VALUES ('legacy', 1, 5, 10, 1)"
        )
        legacy.execute(
            """INSERT INTO player_state_mutations VALUES
               ('legacy-1', 'legacy', 0, NULL, 5, 10, 1, 5, 10, 1)"""
        )
        legacy.close()

        connection = sqlite3.connect(legacy_path, isolation_level=None)
        try:
            migrated = SqlitePlayerStateStore(connection)
            self.assertEqual(
                migrated.verify_integrity(),
                {
                    "snapshots": 1,
                    "mutations": 1,
                    "anchored_snapshots": 0,
                    "legacy_unanchored_snapshots": 1,
                },
            )
        finally:
            connection.close()

    def test_verify_integrity_uses_one_read_snapshot_during_concurrent_commit(self):
        self.db.execute("PRAGMA journal_mode=WAL").fetchone()
        self.store.create("hero", currency=10)
        writer = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(writer.close)
        writer_store = SqlitePlayerStateStore(writer)
        committed = []

        def commit_after_snapshot(statement):
            if (not committed
                    and "FROM player_state_mutations" in statement):
                committed.append(True)
                writer_store.apply(
                    "hero", "concurrent-audit", 0, experience_delta=5
                )

        self.db.set_trace_callback(commit_after_snapshot)
        try:
            result = self.store.verify_integrity()
        finally:
            self.db.set_trace_callback(None)

        self.assertEqual(committed, [True])
        self.assertEqual(
            result,
            {
                "snapshots": 1,
                "mutations": 0,
                "anchored_snapshots": 1,
                "legacy_unanchored_snapshots": 0,
            },
        )
        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.store.get("hero").experience, 5)
        self.assertEqual(
            self.store.verify_integrity(),
            {
                "snapshots": 1,
                "mutations": 1,
                "anchored_snapshots": 1,
                "legacy_unanchored_snapshots": 0,
            },
        )

    def test_verify_integrity_releases_read_transaction_after_failure(self):
        self.store.create("hero")
        self.store.apply("hero", "audit", 0, experience_delta=1)
        self.db.execute(
            "DELETE FROM player_state_mutations WHERE request_id='audit'"
        )
        with self.assertRaisesRegex(PlayerStoreError, "no mutation history"):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_requires_idle_connection(self):
        self.store.create("hero")
        self.db.execute("BEGIN")
        try:
            with self.assertRaisesRegex(ValueError, "active transaction"):
                self.store.verify_integrity()
        finally:
            self.db.rollback()

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
