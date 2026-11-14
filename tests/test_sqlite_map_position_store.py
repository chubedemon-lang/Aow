"""Regression tests for durable synthetic map positions, not APK map rules."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sqlite_map_position_store import (
    MapPositionAlreadyExists,
    MapPositionNotFound,
    MapPositionOperationConflict,
    MapPositionRevisionConflict,
    MapPositionStoreError,
    SqliteMapPositionStore,
)
from server.synthetic_map_position import MapPosition, Position


class _NoMaterializedMapAuditCursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        self._audit_sql = " ".join(str(sql).lower().split())
        return super().execute(sql, parameters)

    def fetchall(self):
        if ("from map_position_snapshots" in getattr(self, "_audit_sql", "")
                or "from map_position_mutations" in getattr(self, "_audit_sql", "")):
            raise AssertionError("map integrity audit must stream table rows")
        return super().fetchall()


class _NoMaterializedMapAuditConnection(sqlite3.Connection):
    def cursor(self, factory=_NoMaterializedMapAuditCursor):
        return super().cursor(factory)

    def execute(self, sql, parameters=()):
        cursor = self.cursor()
        cursor.execute(sql, parameters)
        return cursor


class SqliteMapPositionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "map-position.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.store = SqliteMapPositionStore(self.db)
        self.addCleanup(self.db.close)

    def test_create_and_read_unplaced_snapshot(self):
        snapshot = self.store.create("hero")
        self.assertEqual(snapshot, MapPosition())
        self.assertEqual(self.store.get("hero"), snapshot)

    def test_duplicate_and_missing_snapshot(self):
        self.store.create("hero")
        with self.assertRaises(MapPositionAlreadyExists):
            self.store.create("hero")
        with self.assertRaises(MapPositionNotFound):
            self.store.get("missing")

    def test_enter_move_leave_lifecycle(self):
        self.store.create("hero")
        entered = self.store.enter("hero", "enter-1", 0, 0, 10, -4)
        self.assertFalse(entered.replayed)
        self.assertEqual(entered.snapshot,
                         MapPosition(0, Position(10, -4), 1))
        moved = self.store.move("hero", "move-1", 1, 0, -7, 20)
        self.assertEqual(moved.snapshot,
                         MapPosition(0, Position(-7, 20), 2))
        left = self.store.leave("hero", "leave-1", 2, 0)
        self.assertEqual(left.snapshot, MapPosition(revision=3))
        self.assertEqual(self.store.get("hero"), left.snapshot)

    def test_enter_twice_move_outside_or_leave_wrong_map_rejected(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 4, 0, 0)
        with self.assertRaises(MapPositionStoreError):
            self.store.enter("hero", "enter-again", 1, 5, 1, 1)
        with self.assertRaises(MapPositionStoreError):
            self.store.move("hero", "wrong-map", 1, 5, 1, 1)
        with self.assertRaises(MapPositionStoreError):
            self.store.leave("hero", "wrong-leave", 1, 5)
        self.assertEqual(self.store.get("hero"),
                         MapPosition(4, Position(0, 0), 1))

    def test_stale_revision_is_rejected_without_receipt(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        with self.assertRaises(MapPositionRevisionConflict):
            self.store.move("hero", "stale", 0, 1, 2, 3)
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM map_position_mutations WHERE request_id='stale'"
        ).fetchone()[0], 0)
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_exact_retry_returns_original_receipt_after_later_transition(self):
        self.store.create("hero")
        first = self.store.enter("hero", "same", 0, 1, 2, 3)
        self.store.move("hero", "later", 1, 1, 8, 9)
        replay = self.store.enter("hero", "same", 0, 1, 2, 3)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertEqual(self.store.get("hero"),
                         MapPosition(1, Position(8, 9), 2))

    def test_request_id_cannot_be_reused_for_different_transition(self):
        self.store.create("hero")
        self.store.create("alt")
        self.store.enter("hero", "same", 0, 1, 0, 0)
        with self.assertRaises(MapPositionOperationConflict):
            self.store.enter("hero", "same", 0, 1, 1, 0)
        with self.assertRaises(MapPositionOperationConflict):
            self.store.enter("alt", "same", 0, 1, 0, 0)

    def test_operation_name_is_part_of_idempotency_payload(self):
        self.store.create("hero")
        self.store.enter("hero", "same-operation-key", 0, 1, 0, 0)
        with self.assertRaises(MapPositionOperationConflict):
            self.store.move("hero", "same-operation-key", 0, 1, 1, 1)

    def test_invalid_identifiers_maps_coordinates_and_revisions(self):
        for character_id in ("", " hero", "hero ", "x" * 129, None):
            with self.assertRaises(MapPositionStoreError):
                self.store.create(character_id)
        self.store.create("hero")
        invalid_calls = [
            ("bad-map", True, 0, 0),
            ("bad-map-negative", -1, 0, 0),
            ("bad-map-large", 2**31, 0, 0),
            ("bad-x", 1, True, 0),
            ("bad-y", 1, 0, 1.5),
        ]
        for request_id, map_id, x, y in invalid_calls:
            with self.subTest(request_id=request_id):
                with self.assertRaises(MapPositionStoreError):
                    self.store.enter("hero", request_id, 0, map_id, x, y)
        with self.assertRaises(MapPositionStoreError):
            self.store.enter("hero", "bad-revision", True, 1, 0, 0)
        with self.assertRaises(MapPositionStoreError):
            self.store.enter("hero", "", 0, 1, 0, 0)
        self.assertEqual(self.store.get("hero"), MapPosition())

    def test_reopen_preserves_position_and_receipts(self):
        self.store.create("hero")
        result = self.store.enter("hero", "persist", 0, 9, -10, 11)
        self.db.close()
        reopened = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(reopened.close)
        store = SqliteMapPositionStore(reopened)
        self.assertEqual(store.get("hero"), result.snapshot)
        replay = store.enter("hero", "persist", 0, 9, -10, 11)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, result.snapshot)

    def test_concurrent_duplicate_transition_commits_once(self):
        self.store.create("hero")
        barrier = threading.Barrier(8)

        def enter_once(_):
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            try:
                store = SqliteMapPositionStore(connection)
                barrier.wait(timeout=5)
                return store.enter("hero", "same", 0, 1, 5, 6)
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(enter_once, range(8)))
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertEqual(sum(result.replayed for result in results), 7)
        self.assertTrue(all(result.snapshot == results[0].snapshot
                            for result in results))
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_concurrent_distinct_transitions_use_revision_guard(self):
        self.store.create("hero")
        barrier = threading.Barrier(2)

        def enter_once(request_id, map_id):
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            try:
                store = SqliteMapPositionStore(connection)
                barrier.wait(timeout=5)
                try:
                    return store.enter("hero", request_id, 0, map_id, 0, 0)
                except MapPositionRevisionConflict:
                    return None
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda pair: enter_once(*pair),
                (("left", 1), ("right", 2)),
            ))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_maximum_revision_is_terminal(self):
        self.store.create("hero")
        self.db.execute(
            "UPDATE map_position_snapshots SET revision=? WHERE character_id=?",
            (2**63 - 2, "hero"),
        )
        result = self.store.enter("hero", "last-transition", 2**63 - 2, 1, 0, 0)
        self.assertEqual(result.snapshot.revision, 2**63 - 1)
        with self.assertRaises(MapPositionStoreError):
            self.store.move("hero", "overflow", 2**63 - 1, 1, 1, 1)

    def test_mutations_join_but_do_not_commit_callers_transaction(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (1)")

        self.assertEqual(self.store.create("temporary"), MapPosition())
        entered = self.store.enter(
            "temporary", "inside-caller", 0, 1, 2, 3
        )
        self.assertEqual(
            entered.snapshot, MapPosition(1, Position(2, 3), 1)
        )
        self.assertTrue(self.db.in_transaction)

        self.db.rollback()
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM caller_work"
        ).fetchone()[0], 0)
        with self.assertRaises(MapPositionNotFound):
            self.store.get("temporary")
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM map_position_mutations"
        ).fetchone()[0], 0)

    def test_nested_mutation_failure_rolls_back_only_its_savepoint(self):
        self.store.create("p1")
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.execute(
            """CREATE TRIGGER reject_map_receipt
               BEFORE INSERT ON map_position_mutations
               BEGIN
                   SELECT RAISE(ABORT, 'synthetic receipt failure');
               END"""
        )
        self.db.commit()

        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (7)")
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "synthetic receipt failure"
        ):
            self.store.enter("p1", "failed-enter", 0, 4, 10, 20)

        self.assertTrue(self.db.in_transaction)
        self.assertEqual(self.store.get("p1"), MapPosition(revision=0))
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations"
            ).fetchone()[0],
            0,
        )

        self.db.execute("INSERT INTO caller_work VALUES (8)")
        self.db.commit()
        self.assertEqual(
            self.db.execute(
                "SELECT value FROM caller_work ORDER BY value"
            ).fetchall(),
            [(7,), (8,)],
        )
        self.assertEqual(self.store.get("p1"), MapPosition(revision=0))

    def test_nested_create_conflict_preserves_caller_transaction(self):
        self.store.create("existing")
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()

        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (11)")
        with self.assertRaises(MapPositionAlreadyExists):
            self.store.create("existing")

        self.assertTrue(self.db.in_transaction)
        self.db.execute("INSERT INTO caller_work VALUES (12)")
        self.db.commit()
        self.assertEqual(
            self.db.execute(
                "SELECT value FROM caller_work ORDER BY value"
            ).fetchall(),
            [(11,), (12,)],
        )
        self.assertEqual(self.store.get("existing"), MapPosition())

    def test_constructor_does_not_commit_callers_transaction(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (1)")
        with self.assertRaises(ValueError):
            SqliteMapPositionStore(self.db)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(self.db.execute(
            "SELECT count(*) FROM caller_work"
        ).fetchone()[0], 0)


    def test_integrity_audit_streams_snapshot_and_mutation_rows(self):
        self.store.create("hero")
        self.store.enter("hero", "enter-stream", 0, 2, 10, -4)
        self.store.move("hero", "move-stream", 1, 2, 12, -3)
        self.store.create("alt")
        self.store.enter("alt", "enter-alt-stream", 0, 7, 0, 0)

        streaming_db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None,
            factory=_NoMaterializedMapAuditConnection,
        )
        try:
            streaming_store = SqliteMapPositionStore(streaming_db)
            self.assertEqual(
                streaming_store.verify_integrity(),
                {"snapshots": 2, "mutations": 3},
            )
            self.assertFalse(streaming_db.in_transaction)
        finally:
            streaming_db.close()

    def test_integrity_audit_replays_complete_history(self):
        self.store.create("hero")
        self.store.enter("hero", "enter-1", 0, 2, 10, -4)
        self.store.move("hero", "move-1", 1, 2, 12, -3)
        self.store.leave("hero", "leave-1", 2, 2)
        self.store.create("alt")
        self.store.enter("alt", "enter-alt", 0, 7, 0, 0)
        self.assertEqual(
            self.store.verify_integrity(),
            {"snapshots": 2, "mutations": 4},
        )
        self.assertFalse(self.db.in_transaction)

    def test_integrity_audit_uses_one_read_snapshot_during_concurrent_commit(self):
        self.db.execute("PRAGMA journal_mode=WAL").fetchone()
        self.store.create("hero")
        writer = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(writer.close)
        writer_store = SqliteMapPositionStore(writer)
        committed = []

        def commit_after_snapshot(statement):
            if not committed and "FROM map_position_mutations" in statement:
                committed.append(True)
                writer_store.enter("hero", "concurrent", 0, 1, 2, 3)

        self.db.set_trace_callback(commit_after_snapshot)
        try:
            result = self.store.verify_integrity()
        finally:
            self.db.set_trace_callback(None)

        self.assertEqual(committed, [True])
        self.assertEqual(result, {"snapshots": 1, "mutations": 0})
        self.assertEqual(
            self.store.get("hero"), MapPosition(1, Position(2, 3), 1)
        )
        self.assertEqual(
            self.store.verify_integrity(), {"snapshots": 1, "mutations": 1}
        )

    def test_integrity_audit_releases_read_transaction_after_failure(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        self.db.execute(
            "DELETE FROM map_position_mutations WHERE request_id='enter'"
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_integrity_audit_detects_missing_receipt(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        self.db.execute(
            "DELETE FROM map_position_mutations WHERE request_id='enter'"
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()

    def test_integrity_audit_detects_tampered_result_snapshot(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        self.db.execute(
            "UPDATE map_position_mutations SET result_json=? WHERE request_id=?",
            ('{"map_id":1,"x":99,"y":0,"revision":1}', "enter"),
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()

    def test_integrity_audit_detects_tampered_transition_payload(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        self.db.execute(
            "UPDATE map_position_mutations SET payload_json=? WHERE request_id=?",
            ('{"operation":"enter","map_id":1,"x":99,"y":0}', "enter"),
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()

    def test_integrity_audit_rejects_duplicate_json_keys(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        self.db.execute(
            "UPDATE map_position_mutations SET payload_json=? WHERE request_id=?",
            ('{"operation":"enter","operation":"leave","map_id":1,"x":0,"y":0}', "enter"),
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()

    def test_integrity_audit_detects_current_snapshot_divergence(self):
        self.store.create("hero")
        self.store.enter("hero", "enter", 0, 1, 0, 0)
        self.db.execute(
            "UPDATE map_position_snapshots SET revision=2 WHERE character_id='hero'"
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()

    def test_integrity_audit_detects_foreign_key_orphan(self):
        self.store.create("hero")
        self.db.execute("PRAGMA foreign_keys = OFF")
        self.db.execute(
            """INSERT INTO map_position_mutations
               (request_id, character_id, expected_revision, payload_json,
                result_json, result_revision)
               VALUES ('orphan', 'missing', 0, '{}', '{}', 1)"""
        )
        with self.assertRaises(MapPositionStoreError):
            self.store.verify_integrity()

    def test_integrity_audit_requires_idle_connection(self):
        self.store.create("hero")
        self.db.execute("BEGIN")
        with self.assertRaises(ValueError):
            self.store.verify_integrity()
        self.db.rollback()
        self.assertEqual(
            self.store.verify_integrity(),
            {"snapshots": 1, "mutations": 0},
        )



if __name__ == "__main__":
    unittest.main()
