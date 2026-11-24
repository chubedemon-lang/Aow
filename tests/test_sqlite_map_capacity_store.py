"""Durable synthetic map-capacity tests; no AOW map semantics are inferred."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sqlite_map_capacity_store import (
    MapCapacityConfigurationError,
    MapCapacityExceeded,
    MapCapacityStoreError,
    SqliteMapCapacityStore,
)
from server.sqlite_map_position_store import SqliteMapPositionStore


class SqliteMapCapacityStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "capacity.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(self.db.close)
        self.positions = SqliteMapPositionStore(self.db)
        self.capacity = SqliteMapCapacityStore(self.db)
        for character_id in ("alpha", "bravo", "charlie"):
            self.positions.create(character_id)

    def test_configure_seed_reconcile_and_release(self):
        self.positions.enter("alpha", "alpha-enter", 0, 7, 1, 2)
        self.capacity.configure_map(7, 2)
        self.assertEqual(self.capacity.capacity(7), 2)
        self.assertEqual(self.capacity.members(7), frozenset({"alpha"}))
        self.positions.enter("bravo", "bravo-enter", 0, 7, 3, 4)
        self.assertTrue(self.capacity.reconcile("bravo", 7))
        self.assertFalse(self.capacity.reconcile("bravo", 7))
        self.assertEqual(self.capacity.members(7), frozenset({"alpha", "bravo"}))
        self.positions.leave("bravo", "bravo-leave", 1, 7)
        self.assertTrue(self.capacity.reconcile("bravo", None))
        self.assertEqual(self.capacity.members(7), frozenset({"alpha"}))
        self.assertEqual(
            self.capacity.verify_integrity(),
            {"members": 1, "configured_maps": 1},
        )

    def test_capacity_rejection_does_not_publish_membership(self):
        self.capacity.configure_map(3, 1)
        self.positions.enter("alpha", "first", 0, 3, 0, 0)
        self.capacity.reconcile("alpha", 3)
        self.positions.enter("bravo", "second", 0, 3, 0, 0)
        with self.assertRaises(MapCapacityExceeded):
            self.capacity.reconcile("bravo", 3)
        self.assertEqual(self.capacity.members(3), frozenset({"alpha"}))
        self.assertIsNone(self.db.execute(
            "SELECT map_id FROM map_capacity_members WHERE character_id='bravo'"
        ).fetchone())

    def test_lowering_capacity_below_occupancy_is_atomic(self):
        self.capacity.configure_map(4, 3)
        self.positions.enter("alpha", "a", 0, 4, 0, 0)
        self.capacity.reconcile("alpha", 4)
        self.positions.enter("bravo", "b", 0, 4, 0, 0)
        self.capacity.reconcile("bravo", 4)
        with self.assertRaises(MapCapacityConfigurationError):
            self.capacity.configure_map(4, 1)
        self.assertEqual(self.capacity.capacity(4), 3)
        self.assertEqual(self.capacity.members(4), frozenset({"alpha", "bravo"}))

    def test_reconcile_requires_exact_current_position(self):
        self.capacity.configure_map(7, 1)
        with self.assertRaises(MapCapacityStoreError):
            self.capacity.reconcile("alpha", 7)
        self.assertFalse(self.capacity.members(7))
        with self.assertRaises(MapCapacityStoreError):
            self.capacity.reconcile("missing", None)

    def test_unconfigured_map_is_not_tracked(self):
        self.positions.enter("alpha", "enter", 0, 9, 1, 1)
        self.assertFalse(self.capacity.reconcile("alpha", 9))
        self.assertFalse(self.capacity.members(9))
        self.assertEqual(
            self.capacity.verify_integrity(),
            {"members": 0, "configured_maps": 0},
        )

    def test_verify_integrity_detects_projection_drift_without_repair(self):
        self.capacity.configure_map(7, 1)
        self.positions.enter("alpha", "enter", 0, 7, 1, 1)
        self.capacity.reconcile("alpha", 7)
        self.db.execute(
            "UPDATE map_position_snapshots SET map_id=8 WHERE character_id='alpha'"
        )
        with self.assertRaises(MapCapacityStoreError):
            self.capacity.verify_integrity()
        self.assertEqual(self.capacity.members(7), frozenset({"alpha"}))

    def test_verify_integrity_detects_unconfigured_membership_without_repair(self):
        self.positions.enter("alpha", "unconfigured-enter", 0, 12, 1, 1)
        self.db.execute(
            "INSERT INTO map_capacity_members(character_id, map_id) VALUES (?, ?)",
            ("alpha", 12),
        )
        with self.assertRaises(MapCapacityStoreError):
            self.capacity.verify_integrity()
        self.assertEqual(self.capacity.members(12), frozenset({"alpha"}))

    def test_constructor_rejects_non_enforcing_check_constraints(self):
        for weak_table in ("map_capacity_limits", "map_capacity_members"):
            with self.subTest(weak_table=weak_table):
                self.db.execute("DROP TABLE map_capacity_members")
                self.db.execute("DROP TABLE map_capacity_limits")

                weak = weak_table == "map_capacity_limits"
                map_id_check = "CHECK(1)" if weak else (
                    "CHECK(map_id BETWEEN 0 AND 2147483647)"
                )
                capacity_check = "CHECK(1)" if weak else (
                    "CHECK(capacity BETWEEN 1 AND 100000)"
                )
                self.db.execute(
                    "CREATE TABLE map_capacity_limits ("
                    "map_id INTEGER PRIMARY KEY " + map_id_check + ", "
                    "capacity INTEGER NOT NULL " + capacity_check + ")"
                )

                weak = weak_table == "map_capacity_members"
                character_check = "CHECK(1)" if weak else (
                    "CHECK(length(character_id) BETWEEN 1 AND 128)"
                )
                member_map_check = "CHECK(1)" if weak else (
                    "CHECK(map_id BETWEEN 0 AND 2147483647)"
                )
                self.db.execute(
                    "CREATE TABLE map_capacity_members ("
                    "character_id TEXT PRIMARY KEY " + character_check + ", "
                    "map_id INTEGER NOT NULL " + member_map_check + ", "
                    "FOREIGN KEY(character_id) "
                    "REFERENCES map_position_snapshots(character_id) "
                    "ON DELETE CASCADE)"
                )
                self.db.execute(
                    "CREATE INDEX map_capacity_members_map "
                    "ON map_capacity_members(map_id, character_id)"
                )

                with self.assertRaises(MapCapacityStoreError):
                    SqliteMapCapacityStore(self.db)
                self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_rejects_untrimmed_persisted_character_id(self):
        self.capacity.configure_map(7, 1)
        self.db.execute(
            """INSERT INTO map_position_snapshots
               (character_id, map_id, x, y, revision)
               VALUES (?, ?, ?, ?, ?)""",
            (" alpha", 7, 1, 1, 0),
        )
        self.db.execute(
            "INSERT INTO map_capacity_members(character_id, map_id) VALUES (?, ?)",
            (" alpha", 7),
        )

        with self.assertRaises(MapCapacityStoreError):
            self.capacity.verify_integrity()
        self.assertEqual(
            self.db.execute(
                "SELECT character_id, map_id FROM map_capacity_members"
            ).fetchall(),
            [(" alpha", 7)],
        )

    def test_two_connections_enforce_one_slot_across_writers(self):
        self.capacity.configure_map(11, 1)
        barrier = threading.Barrier(2)

        def attempt(character_id):
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                positions = SqliteMapPositionStore(connection)
                capacity = SqliteMapCapacityStore(connection)
                positions.enter(
                    character_id, "enter-" + character_id, 0, 11, 0, 0
                )
                barrier.wait(timeout=5)
                try:
                    capacity.reconcile(character_id, 11)
                    return "accepted"
                except MapCapacityExceeded:
                    return "full"
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, ("alpha", "bravo")))
        self.assertCountEqual(outcomes, ["accepted", "full"])
        self.assertEqual(len(self.capacity.members(11)), 1)

    def test_caller_transaction_owns_commit_and_rollback(self):
        self.capacity.configure_map(2, 1)
        self.positions.enter("alpha", "enter-alpha", 0, 2, 0, 0)
        self.db.execute("BEGIN")
        self.capacity.reconcile("alpha", 2)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertFalse(self.capacity.members(2))

    def test_invalid_inputs_are_rejected(self):
        for map_id in (True, -1, 2**31, "7"):
            with self.subTest(map_id=map_id), self.assertRaises(MapCapacityStoreError):
                self.capacity.configure_map(map_id, 1)
        for capacity in (True, 0, 100001, 1.5):
            with self.subTest(capacity=capacity), self.assertRaises(MapCapacityStoreError):
                self.capacity.configure_map(1, capacity)
        for character_id in ("", " alpha", "alpha ", "x" * 129, None):
            with self.subTest(character_id=character_id), self.assertRaises(MapCapacityStoreError):
                self.capacity.reconcile(character_id, None)

    def test_writes_and_integrity_audit_fail_closed_if_foreign_keys_are_disabled(self):
        self.positions.enter("alpha", "enter", 0, 7, 0, 0)
        self.db.execute("PRAGMA foreign_keys = OFF")

        with self.assertRaisesRegex(MapCapacityStoreError, "foreign keys are disabled"):
            self.capacity.configure_map(7, 1)
        self.assertIsNone(self.db.execute(
            "SELECT capacity FROM map_capacity_limits WHERE map_id=7"
        ).fetchone())
        self.assertFalse(self.db.in_transaction)

        with self.assertRaisesRegex(MapCapacityStoreError, "foreign keys are disabled"):
            self.capacity.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_writes_and_integrity_audit_fail_closed_if_check_constraints_are_disabled(self):
        self.db.execute("PRAGMA ignore_check_constraints = ON")

        with self.assertRaisesRegex(MapCapacityStoreError, "CHECK constraints are disabled"):
            self.capacity.configure_map(7, 1)
        self.assertIsNone(self.db.execute(
            "SELECT capacity FROM map_capacity_limits WHERE map_id=7"
        ).fetchone())
        self.assertFalse(self.db.in_transaction)

        with self.assertRaisesRegex(MapCapacityStoreError, "CHECK constraints are disabled"):
            self.capacity.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_constructor_requires_position_schema_and_idle_connection(self):
        empty = sqlite3.connect(":memory:", isolation_level=None)
        try:
            with self.assertRaises(MapCapacityStoreError):
                SqliteMapCapacityStore(empty)
            self.assertFalse(empty.in_transaction)
            self.assertEqual(empty.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='map_capacity_limits'"
            ).fetchone()[0], 0)
        finally:
            empty.close()

        self.db.execute("BEGIN")
        try:
            with self.assertRaises(ValueError):
                SqliteMapCapacityStore(self.db)
            self.assertTrue(self.db.in_transaction)
        finally:
            self.db.rollback()


    def test_read_methods_fail_closed_if_foreign_keys_are_disabled(self):
        self.capacity.configure_map(7, 1)
        self.db.execute("PRAGMA foreign_keys = OFF")

        for read in (self.capacity.capacity, self.capacity.members):
            with self.subTest(read=read.__name__):
                with self.assertRaisesRegex(
                    MapCapacityStoreError, "foreign keys are disabled"
                ):
                    read(7)
                self.assertFalse(self.db.in_transaction)

    def test_read_methods_fail_closed_if_check_constraints_are_disabled(self):
        self.capacity.configure_map(7, 1)
        self.db.execute("PRAGMA ignore_check_constraints = ON")

        for read in (self.capacity.capacity, self.capacity.members):
            with self.subTest(read=read.__name__):
                with self.assertRaisesRegex(
                    MapCapacityStoreError, "CHECK constraints are disabled"
                ):
                    read(7)
                self.assertFalse(self.db.in_transaction)


if __name__ == "__main__":
    unittest.main()
