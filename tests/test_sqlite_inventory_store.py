"""Regression tests for durable synthetic inventory; not APK item tests."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sqlite_inventory_store import (
    InventoryAlreadyExists,
    InventoryNotFound,
    InventoryOperationConflict,
    InventoryRevisionConflict,
    InventoryStoreError,
    SqliteInventoryStore,
)


class HostileText(str):
    def __bool__(self):
        raise AssertionError("custom text truthiness hook must not run")

    def __len__(self):
        raise AssertionError("custom text length hook must not run")

    def strip(self, *args, **kwargs):
        raise AssertionError("custom text strip hook must not run")


class HostileList(list):
    def __len__(self):
        raise AssertionError("custom list length hook must not run")

    def __iter__(self):
        raise AssertionError("custom list iterator must not run")


class HostileTuple(tuple):
    def __len__(self):
        raise AssertionError("custom tuple length hook must not run")

    def __iter__(self):
        raise AssertionError("custom tuple iterator must not run")


class SqliteInventoryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "inventory.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.store = SqliteInventoryStore(self.db)
        self.addCleanup(self.db.close)

    def test_rejects_text_subclasses_before_custom_hooks(self):
        self.store.create("hero")
        hostile = HostileText("hero")
        operations = (
            lambda: self.store.create(hostile),
            lambda: self.store.get(hostile),
            lambda: self.store.apply(hostile, "request", 0, [("potion", 1)]),
            lambda: self.store.apply("hero", HostileText("request"), 0,
                                     [("potion", 1)]),
            lambda: self.store.apply("hero", "item-request", 0,
                                     [(HostileText("potion"), 1)]),
        )
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                with self.assertRaises(InventoryStoreError):
                    operation()

        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.store.get("hero").items, ())
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            0,
        )

    def test_rejects_collection_subclasses_before_custom_hooks(self):
        self.store.create("hero")
        hostile_changes = (
            HostileList([("potion", 1)]),
            HostileTuple([("potion", 1)]),
        )
        for index, changes in enumerate(hostile_changes):
            with self.subTest(collection=index):
                with self.assertRaisesRegex(
                    InventoryStoreError, "bounded sequence"
                ):
                    self.store.apply("hero", "collection-" + str(index), 0, changes)

        hostile_entries = (
            HostileList(["potion", 1]),
            HostileTuple(["potion", 1]),
        )
        for index, entry in enumerate(hostile_entries):
            with self.subTest(entry=index):
                with self.assertRaisesRegex(
                    InventoryStoreError, "invalid inventory change"
                ):
                    self.store.apply(
                        "hero", "entry-" + str(index), 0, [entry]
                    )

        self.assertFalse(self.db.in_transaction)
        self.assertEqual(self.store.get("hero").items, ())
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            0,
        )

    def test_constructor_rejects_connection_subclasses_before_hooks(self):
        class HostileConnection(sqlite3.Connection):
            @property
            def in_transaction(self):
                raise AssertionError("custom transaction-state hook must not run")

        connection = sqlite3.connect(":memory:", factory=HostileConnection)
        try:
            with self.assertRaisesRegex(TypeError, "sqlite connection"):
                SqliteInventoryStore(connection)
        finally:
            sqlite3.Connection.close(connection)

    def test_create_and_read_empty_inventory(self):
        expected = self.store.create("hero", capacity=3, max_stack=10)
        self.assertEqual(self.store.get("hero"), expected)
        self.assertEqual(expected.items, ())
        self.assertEqual(expected.revision, 0)

    def test_duplicate_and_missing_inventory(self):
        self.store.create("hero")
        with self.assertRaises(InventoryAlreadyExists):
            self.store.create("hero")
        with self.assertRaises(InventoryNotFound):
            self.store.get("missing")

    def test_atomic_mutation_and_revision(self):
        self.store.create("hero", capacity=3, max_stack=10)
        result = self.store.apply("hero", "grant-1", 0, [("potion", 5)])
        self.assertFalse(result.replayed)
        self.assertEqual(result.snapshot.count("potion"), 5)
        self.assertEqual(result.snapshot.revision, 1)
        result = self.store.apply("hero", "use-1", 1, [("potion", -2)])
        self.assertEqual(result.snapshot.count("potion"), 3)
        self.assertEqual(result.snapshot.revision, 2)

    def test_duplicate_deltas_are_aggregated_and_order_independent(self):
        self.store.create("hero", max_stack=10)
        result = self.store.apply(
            "hero", "batch-1", 0, [("potion", 3), ("ore", 2), ("potion", 2)]
        )
        self.assertEqual(result.snapshot.items, (("ore", 2), ("potion", 5)))
        replay = self.store.apply(
            "hero", "batch-1", 0, [("potion", 2), ("ore", 2), ("potion", 3)]
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, result.snapshot)

    def test_exact_retry_returns_original_receipt_after_later_mutation(self):
        self.store.create("hero", max_stack=20)
        first = self.store.apply("hero", "grant-1", 0, [("potion", 5)])
        self.store.apply("hero", "use-1", 1, [("potion", -2)])
        replay = self.store.apply("hero", "grant-1", 0, [("potion", 5)])
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertEqual(self.store.get("hero").count("potion"), 3)
        self.assertEqual(self.store.get("hero").revision, 2)

    def test_request_id_cannot_be_reused_for_another_payload_or_character(self):
        self.store.create("hero")
        self.store.create("alt")
        self.store.apply("hero", "same-id", 0, [("potion", 1)])
        with self.assertRaises(InventoryOperationConflict):
            self.store.apply("hero", "same-id", 0, [("potion", 2)])
        with self.assertRaises(InventoryOperationConflict):
            self.store.apply("alt", "same-id", 0, [("potion", 1)])

    def test_stale_revision_is_rejected_without_receipt(self):
        self.store.create("hero")
        self.store.apply("hero", "first", 0, [("potion", 1)])
        with self.assertRaises(InventoryRevisionConflict):
            self.store.apply("hero", "stale", 0, [("ore", 1)])
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM inventory_mutations WHERE request_id='stale'"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(self.store.get("hero").items, (("potion", 1),))

    def test_underflow_stack_and_capacity_fail_atomically(self):
        self.store.create("hero", capacity=1, max_stack=3)
        self.store.apply("hero", "first", 0, [("potion", 2)])
        before = self.store.get("hero")
        cases = [
            ("underflow", [("potion", -3)]),
            ("stack-overflow", [("potion", 2)]),
            ("capacity", [("ore", 1)]),
        ]
        for request_id, changes in cases:
            with self.subTest(request_id=request_id), self.assertRaises(InventoryStoreError):
                self.store.apply("hero", request_id, 1, changes)
            self.assertEqual(self.store.get("hero"), before)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            1,
        )

    def test_cancelled_batch_is_rejected_without_revision_change(self):
        self.store.create("hero")
        with self.assertRaisesRegex(InventoryStoreError, "empty"):
            self.store.apply("hero", "cancel", 0, [("potion", 2), ("potion", -2)])
        self.assertEqual(self.store.get("hero").revision, 0)

    def test_invalid_inputs_do_not_mutate(self):
        self.store.create("hero")
        invalid = [
            ("", 0, [("potion", 1)]),
            ("bad", True, [("potion", 1)]),
            ("bad", -1, [("potion", 1)]),
            ("bad", 0, None),
            ("bad", 0, [("bad item", 1)]),
            ("bad", 0, [("potion", True)]),
            ("bad", 0, [("potion", 0)]),
            ("bad", 0, [("potion", 2**31)]),
            ("bad", 0, [("potion", 1, 2)]),
        ]
        for request_id, revision, changes in invalid:
            with self.subTest(request_id=request_id, changes=changes), self.assertRaises(InventoryStoreError):
                self.store.apply("hero", request_id, revision, changes)
        for kwargs in ({"capacity": 0}, {"capacity": True},
                       {"max_stack": 0}, {"max_stack": False},
                       {"capacity": 4097}, {"max_stack": 2**31}):
            with self.subTest(kwargs=kwargs), self.assertRaises(InventoryStoreError):
                self.store.create("other", **kwargs)
        self.assertEqual(self.store.get("hero").revision, 0)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            0,
        )

    def test_batch_limit_is_enforced(self):
        self.store.create("hero")
        with self.assertRaises(InventoryStoreError):
            self.store.apply("hero", "large", 0, [("potion", 1)] * 4097)
        self.assertEqual(self.store.get("hero").revision, 0)

    def test_inventory_and_receipts_survive_reopen(self):
        self.store.create("hero")
        expected = self.store.apply("hero", "persist", 0, [("potion", 4)])
        self.db.close()
        reopened = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(reopened.close)
        store = SqliteInventoryStore(reopened)
        self.assertEqual(store.get("hero"), expected.snapshot)
        replay = store.apply("hero", "persist", 0, [("potion", 4)])
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, expected.snapshot)

    def test_concurrent_same_request_has_one_mutation(self):
        self.store.create("hero", max_stack=20)
        barrier = threading.Barrier(8)

        def apply_once(_):
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            try:
                store = SqliteInventoryStore(connection)
                barrier.wait(timeout=5)
                return store.apply("hero", "same", 0, [("potion", 2)])
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(apply_once, range(8)))
        self.assertEqual(sum(not result.replayed for result in results), 1)
        self.assertEqual(sum(result.replayed for result in results), 7)
        self.assertTrue(all(result.snapshot == results[0].snapshot for result in results))
        self.assertEqual(self.store.get("hero").count("potion"), 2)
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_concurrent_distinct_requests_use_revision_guard(self):
        self.store.create("hero", max_stack=20)
        barrier = threading.Barrier(2)

        def apply_once(request_id):
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            try:
                store = SqliteInventoryStore(connection)
                barrier.wait(timeout=5)
                try:
                    return store.apply("hero", request_id, 0, [("potion", 1)])
                except InventoryRevisionConflict:
                    return None
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(apply_once, ("left", "right")))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.store.get("hero").count("potion"), 1)
        self.assertEqual(self.store.get("hero").revision, 1)

    def test_get_rejects_corrupt_persisted_sqlite_storage_types(self):
        self.store.create("hero", capacity=3, max_stack=10)
        self.store.apply("hero", "seed", 0, [("potion", 2)])
        corruptions = (
            ("capacity REAL",
             "UPDATE inventory_snapshots SET capacity=? WHERE character_id=?",
             (2.5, "hero"),
             "UPDATE inventory_snapshots SET capacity=3 WHERE character_id=?",
             ("hero",)),
            ("max_stack REAL",
             "UPDATE inventory_snapshots SET max_stack=? WHERE character_id=?",
             (10.5, "hero"),
             "UPDATE inventory_snapshots SET max_stack=10 WHERE character_id=?",
             ("hero",)),
            ("revision REAL",
             "UPDATE inventory_snapshots SET revision=? WHERE character_id=?",
             (1.5, "hero"),
             "UPDATE inventory_snapshots SET revision=1 WHERE character_id=?",
             ("hero",)),
            ("quantity REAL",
             "UPDATE inventory_items SET quantity=? WHERE character_id=?",
             (1.5, "hero"),
             "UPDATE inventory_items SET quantity=2 WHERE character_id=?",
             ("hero",)),
            ("item ID BLOB",
             "UPDATE inventory_items SET item_id=CAST(item_id AS BLOB) WHERE character_id=?",
             ("hero",),
             "UPDATE inventory_items SET item_id=CAST(item_id AS TEXT) WHERE character_id=?",
             ("hero",)),
        )
        for label, corrupt_sql, corrupt_args, restore_sql, restore_args in corruptions:
            with self.subTest(field=label):
                self.db.execute("PRAGMA ignore_check_constraints=ON")
                try:
                    self.db.execute(corrupt_sql, corrupt_args)
                    with self.assertRaises(InventoryStoreError):
                        self.store.get("hero")
                    self.db.execute(restore_sql, restore_args)
                finally:
                    self.db.execute("PRAGMA ignore_check_constraints=OFF")
        self.assertEqual(self.store.get("hero").items, (("potion", 2),))

    def test_apply_rejects_corrupt_persisted_sqlite_storage_types_before_mutation(self):
        self.store.create("hero", capacity=3, max_stack=10)
        self.store.apply("hero", "seed", 0, [("potion", 2)])
        corruptions = (
            ("capacity REAL",
             "UPDATE inventory_snapshots SET capacity=? WHERE character_id=?",
             (2.5, "hero"),
             "UPDATE inventory_snapshots SET capacity=3 WHERE character_id=?",
             ("hero",)),
            ("max_stack REAL",
             "UPDATE inventory_snapshots SET max_stack=? WHERE character_id=?",
             (10.5, "hero"),
             "UPDATE inventory_snapshots SET max_stack=10 WHERE character_id=?",
             ("hero",)),
            ("revision REAL",
             "UPDATE inventory_snapshots SET revision=? WHERE character_id=?",
             (1.5, "hero"),
             "UPDATE inventory_snapshots SET revision=1 WHERE character_id=?",
             ("hero",)),
            ("quantity REAL",
             "UPDATE inventory_items SET quantity=? WHERE character_id=?",
             (1.5, "hero"),
             "UPDATE inventory_items SET quantity=2 WHERE character_id=?",
             ("hero",)),
            ("item ID BLOB",
             "UPDATE inventory_items SET item_id=CAST(item_id AS BLOB) WHERE character_id=?",
             ("hero",),
             "UPDATE inventory_items SET item_id=CAST(item_id AS TEXT) WHERE character_id=?",
             ("hero",)),
        )
        self.db.execute("PRAGMA ignore_check_constraints=ON")
        try:
            for index, (
                label, corrupt_sql, corrupt_args, restore_sql, restore_args
            ) in enumerate(corruptions):
                with self.subTest(field=label):
                    self.db.execute(corrupt_sql, corrupt_args)
                    with self.assertRaises(InventoryStoreError):
                        self.store.apply(
                            "hero", "corrupt-read-" + str(index), 1, [("potion", 1)]
                        )
                    self.db.execute(restore_sql, restore_args)
        finally:
            self.db.execute("PRAGMA ignore_check_constraints=OFF")
        self.assertEqual(self.store.get("hero").items, (("potion", 2),))
        self.assertEqual(self.store.get("hero").revision, 1)
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM inventory_mutations").fetchone()[0],
            1,
        )

    def test_constructor_does_not_commit_callers_transaction(self):
        self.db.execute("CREATE TABLE caller_work (value INTEGER)")
        self.db.commit()
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES (1)")
        with self.assertRaises(ValueError):
            SqliteInventoryStore(self.db)
        self.assertTrue(self.db.in_transaction)
        self.db.rollback()
        self.assertEqual(
            self.db.execute("SELECT count(*) FROM caller_work").fetchone()[0],
            0,
        )


    def test_verify_integrity_accepts_empty_and_mutated_histories(self):
        self.store.create("hero", capacity=3, max_stack=10)
        self.store.create("other")
        self.store.apply("hero", "audit-first", 0, [("potion", 5)])
        self.store.apply("hero", "audit-second", 1, [("potion", -2)])
        self.assertEqual(
            self.store.verify_integrity(),
            {
                "snapshots": 2,
                "items": 1,
                "mutations": 2,
                "anchored_snapshots": 2,
                "legacy_unanchored_snapshots": 0,
            },
        )

    def test_verify_integrity_rejects_missing_creation_receipt(self):
        self.store.create("hero")
        self.db.execute(
            "DELETE FROM inventory_creations WHERE character_id='hero'"
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "creation receipt is missing"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_rejects_tampered_creation_baseline(self):
        self.store.create("hero", capacity=3, max_stack=10)
        self.db.execute(
            "UPDATE inventory_creations SET baseline_json=? "
            "WHERE character_id='hero'",
            ('{"character_id":"hero","capacity":3,"max_stack":10,'
             '"revision":0,"items":[["gem",1]]}',),
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "invalid inventory creation baseline"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_rejects_unrecorded_initial_items(self):
        self.store.create("hero", capacity=3, max_stack=10)
        self.store.apply("hero", "audit-first", 0, [("potion", 2)])
        self.db.execute(
            "UPDATE inventory_mutations SET result_json=? "
            "WHERE request_id='audit-first'",
            ('{"character_id":"hero","capacity":3,"max_stack":10,'
             '"revision":1,"items":[["gem",1],["potion",2]]}',),
        )
        self.db.execute(
            "INSERT INTO inventory_items (character_id,item_id,quantity) "
            "VALUES ('hero','gem',1)"
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "receipt does not match mutation history"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_create_and_creation_receipt_are_atomic(self):
        self.db.execute(
            """CREATE TRIGGER reject_inventory_creation_receipt
               BEFORE INSERT ON inventory_creations
               BEGIN SELECT RAISE(ABORT, 'blocked'); END"""
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create("hero")
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM inventory_snapshots WHERE character_id='hero'"
            ).fetchone()[0],
            0,
        )
        self.assertFalse(self.db.in_transaction)

    def test_create_failure_inside_caller_transaction_preserves_prior_work(self):
        self.db.execute("CREATE TABLE caller_work (value TEXT)")
        self.db.execute(
            """CREATE TRIGGER reject_nested_inventory_creation_receipt
               BEFORE INSERT ON inventory_creations
               BEGIN SELECT RAISE(ABORT, 'blocked'); END"""
        )
        self.db.execute("BEGIN")
        self.db.execute("INSERT INTO caller_work VALUES ('before')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.create("nested-hero")
        self.assertTrue(self.db.in_transaction)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM inventory_snapshots "
                "WHERE character_id='nested-hero'"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.db.execute("SELECT value FROM caller_work").fetchall(),
            [("before",)],
        )
        self.db.rollback()

    def test_legacy_inventory_rows_remain_unanchored_after_migration(self):
        legacy = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(legacy.close)
        legacy.executescript(
            """CREATE TABLE inventory_snapshots (
                   character_id TEXT PRIMARY KEY,
                   capacity INTEGER NOT NULL,
                   max_stack INTEGER NOT NULL,
                   revision INTEGER NOT NULL
               );
               CREATE TABLE inventory_items (
                   character_id TEXT NOT NULL,
                   item_id TEXT NOT NULL,
                   quantity INTEGER NOT NULL,
                   PRIMARY KEY(character_id,item_id)
               );
               CREATE TABLE inventory_mutations (
                   request_id TEXT PRIMARY KEY,
                   character_id TEXT NOT NULL,
                   expected_revision INTEGER NOT NULL,
                   payload_json TEXT NOT NULL,
                   result_json TEXT NOT NULL,
                   result_revision INTEGER NOT NULL
               );
               INSERT INTO inventory_snapshots
                   VALUES ('legacy',20,99,1);
               INSERT INTO inventory_items VALUES ('legacy','potion',2);
               INSERT INTO inventory_mutations VALUES (
                   'legacy-first','legacy',0,'[["potion",2]]',
                   '{"character_id":"legacy","capacity":20,"max_stack":99,"revision":1,"items":[["potion",2]]}',1
               );"""
        )
        migrated = SqliteInventoryStore(legacy)
        self.assertEqual(
            migrated.verify_integrity(),
            {
                "snapshots": 1,
                "items": 1,
                "mutations": 1,
                "anchored_snapshots": 0,
                "legacy_unanchored_snapshots": 1,
            },
        )
        migrated.create("new")
        self.assertEqual(
            migrated.verify_integrity()["anchored_snapshots"], 1
        )
        self.assertEqual(
            migrated.verify_integrity()["legacy_unanchored_snapshots"], 1
        )

    def test_verify_integrity_rejects_missing_first_receipt(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-first", 0, [("potion", 2)])
        self.store.apply("hero", "audit-second", 1, [("potion", 1)])
        self.db.execute(
            "DELETE FROM inventory_mutations WHERE request_id='audit-first'"
        )
        with self.assertRaisesRegex(InventoryStoreError, "history has a gap"):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_rejects_tampered_intermediate_receipt(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-first", 0, [("potion", 2)])
        self.store.apply("hero", "audit-second", 1, [("potion", 1)])
        self.db.execute(
            """UPDATE inventory_mutations SET result_json=?
               WHERE request_id='audit-first'""",
            ('{"character_id":"hero","capacity":20,"max_stack":99,'
             '"revision":1,"items":[["potion",3]]}',),
        )
        with self.assertRaisesRegex(InventoryStoreError, "receipt does not match"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_invalid_payload_json(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-first", 0, [("potion", 2)])
        self.db.execute(
            "UPDATE inventory_mutations SET payload_json='not-json' "
            "WHERE request_id='audit-first'"
        )
        with self.assertRaisesRegex(InventoryStoreError, "mutation payload"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_oversized_receipt_json(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-large-receipt", 0, [("potion", 1)])
        oversized = " " * (512 * 1024 + 1)
        self.db.execute(
            "UPDATE inventory_mutations SET result_json=? WHERE request_id=?",
            (oversized, "audit-large-receipt"),
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "invalid inventory receipt snapshot JSON"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_rejects_oversized_mutation_payload_json(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-large-payload", 0, [("potion", 1)])
        oversized = " " * (512 * 1024 + 1)
        self.db.execute(
            "UPDATE inventory_mutations SET payload_json=? WHERE request_id=?",
            (oversized, "audit-large-payload"),
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "invalid inventory mutation payload"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_normalizes_deeply_nested_receipt_json_failure(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-deep-receipt", 0, [("potion", 1)])
        deeply_nested = "[" * 2000 + "]" * 2000
        self.db.execute(
            "UPDATE inventory_mutations SET result_json=? WHERE request_id=?",
            (deeply_nested, "audit-deep-receipt"),
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "invalid inventory receipt snapshot"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_normalizes_deeply_nested_payload_json_failure(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-deep-payload", 0, [("potion", 1)])
        deeply_nested = "[" * 2000 + "]" * 2000
        self.db.execute(
            "UPDATE inventory_mutations SET payload_json=? WHERE request_id=?",
            (deeply_nested, "audit-deep-payload"),
        )
        with self.assertRaisesRegex(
            InventoryStoreError, "invalid inventory mutation payload"
        ):
            self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)

    def test_verify_integrity_rejects_capacity_overflow_in_stored_items(self):
        self.store.create("hero", capacity=1, max_stack=10)
        self.db.executemany(
            "INSERT INTO inventory_items(character_id,item_id,quantity) "
            "VALUES ('hero',?,1)",
            (("potion",), ("gem",)),
        )
        with self.assertRaisesRegex(InventoryStoreError, "exceeds capacity"):
            self.store.verify_integrity()

    def test_verify_integrity_rejects_boolean_integer_in_receipt(self):
        self.store.create("hero")
        self.store.apply("hero", "audit-first", 0, [("potion", 1)])
        self.db.execute(
            """UPDATE inventory_mutations SET result_json=?
               WHERE request_id='audit-first'""",
            ('{"character_id":"hero","capacity":true,"max_stack":99,'
             '"revision":1,"items":[["potion",1]]}',),
        )
        with self.assertRaisesRegex(InventoryStoreError, "receipt snapshot"):
            self.store.verify_integrity()

    def test_verify_integrity_accepts_shop_and_quest_inventory_receipts(self):
        from server.sqlite_player_state_store import SqlitePlayerStateStore
        from server.sqlite_shop_store import ShopOffer, SqliteShopStore
        from server.sqlite_quest_inventory_award_store import (
            SqliteQuestInventoryAwardStore,
        )

        players = SqlitePlayerStateStore(self.db)
        players.create("hero", currency=100)
        self.store.create("hero", capacity=10, max_stack=20)
        shop = SqliteShopStore(
            self.db, offers={"potion": ShopOffer("potion", "potion", 5)}
        )
        shop.purchase("hero", "buy-once", 0, 0, "potion", 2)
        awards = SqliteQuestInventoryAwardStore(self.db, self.store)
        awards.grant_once("hero", "quest-once", 1, 42, "gem", 2)
        self.assertEqual(
            self.store.verify_integrity(),
            {"snapshots": 1, "items": 2, "mutations": 2},
        )

    def test_verify_integrity_uses_one_snapshot_during_concurrent_mutation(self):
        self.db.execute("PRAGMA journal_mode=WAL")
        self.store.create("hero", capacity=3, max_stack=10)
        self.store.apply("hero", "before-audit", 0, [("potion", 1)])

        writer = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        self.addCleanup(writer.close)
        writer_store = SqliteInventoryStore(writer)

        reader = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.addCleanup(reader.close)
        reader_store = SqliteInventoryStore(reader)

        entered = threading.Event()
        release = threading.Event()
        trace_state = {"paused": False}

        def pause_before_snapshot_query(statement):
            if (not trace_state["paused"]
                    and "SELECT character_id, capacity, max_stack, revision" in statement):
                trace_state["paused"] = True
                entered.set()
                release.wait(5)

        # SQLite invokes this trace callback after inventory_items was read and
        # immediately before inventory_snapshots is queried.
        reader.set_trace_callback(pause_before_snapshot_query)
        outcome = {}

        def audit():
            try:
                outcome["result"] = reader_store.verify_integrity()
            except BaseException as exc:
                outcome["error"] = exc

        thread = threading.Thread(target=audit)
        thread.start()
        reached_query = entered.wait(5)
        try:
            if reached_query:
                writer_store.apply(
                    "hero", "during-audit", 1, [("potion", 1)]
                )
        finally:
            release.set()
            thread.join(5)
            reader.set_trace_callback(None)

        self.assertTrue(
            reached_query,
            f"audit did not reach the paused snapshot query; outcome={outcome!r}",
        )
        self.assertFalse(thread.is_alive())
        self.assertNotIn("error", outcome)
        self.assertEqual(
            outcome["result"],
            {"snapshots": 1, "items": 1, "mutations": 1},
        )
        self.assertFalse(reader.in_transaction)
        self.assertEqual(self.store.get("hero").revision, 2)

    def test_verify_integrity_is_read_only_and_requires_idle_connection(self):
        self.store.create("hero")
        with open(self.path, "rb") as source:
            before = source.read()
        self.store.verify_integrity()
        self.assertFalse(self.db.in_transaction)
        with open(self.path, "rb") as source:
            after = source.read()
        self.assertEqual(after, before)

        self.db.execute("BEGIN")
        with self.assertRaisesRegex(ValueError, "active transaction"):
            self.store.verify_integrity()
        self.db.rollback()


    def test_replay_rejects_duplicate_json_keys_in_receipt_snapshot(self):
        self.store.create("hero")
        self.store.apply("hero", "tampered-duplicate", 0, [("potion", 1)])
        self.db.execute(
            "UPDATE inventory_mutations SET result_json=? WHERE request_id=?",
            ('{"character_id":"hero","character_id":"hero","capacity":20,'
             '"max_stack":99,"revision":1,"items":[["potion",1]]}',
             "tampered-duplicate"),
        )
        with self.assertRaisesRegex(InventoryStoreError, "duplicate JSON key"):
            self.store.apply("hero", "tampered-duplicate", 0, [("potion", 1)])

    def test_replay_rejects_receipt_for_another_character(self):
        self.store.create("hero")
        self.store.apply("hero", "tampered-owner", 0, [("potion", 1)])
        self.db.execute(
            "UPDATE inventory_mutations SET result_json=? WHERE request_id=?",
            ('{"character_id":"other","capacity":20,"max_stack":99,'
             '"revision":1,"items":[["potion",1]]}', "tampered-owner"),
        )
        with self.assertRaisesRegex(InventoryStoreError, "character mismatch"):
            self.store.apply("hero", "tampered-owner", 0, [("potion", 1)])

    def test_replay_rejects_boolean_quantities_and_noncanonical_item_order(self):
        cases = (
            ('{"character_id":"hero","capacity":20,"max_stack":99,'
             '"revision":1,"items":[["potion",true]]}', "boolean quantity"),
            ('{"character_id":"hero","capacity":20,"max_stack":99,'
             '"revision":1,"items":[["potion",1],["apple",1]]}', "item order"),
        )
        for index, (receipt, label) in enumerate(cases):
            with self.subTest(case=label):
                request_id = "tampered-shape-" + str(index)
                self.store.create("hero-" + str(index))
                character_id = "hero-" + str(index)
                self.store.apply(character_id, request_id, 0, [("potion", 1)])
                receipt = receipt.replace('"hero"', '"' + character_id + '"')
                self.db.execute(
                    "UPDATE inventory_mutations SET result_json=? WHERE request_id=?",
                    (receipt, request_id),
                )
                with self.assertRaises(InventoryStoreError):
                    self.store.apply(character_id, request_id, 0, [("potion", 1)])

    def test_replay_rejects_receipt_revision_mismatch(self):
        self.store.create("hero")
        self.store.apply("hero", "tampered-revision", 0, [("potion", 1)])
        self.db.execute(
            "UPDATE inventory_mutations SET result_revision=2 WHERE request_id=?",
            ("tampered-revision",),
        )
        with self.assertRaisesRegex(InventoryStoreError, "receipt revision"):
            self.store.apply("hero", "tampered-revision", 0, [("potion", 1)])

    def test_replay_rejects_non_finite_receipt_values(self):
        self.store.create("hero")
        self.store.apply("hero", "tampered-float", 0, [("potion", 1)])
        self.db.execute(
            "UPDATE inventory_mutations SET result_json=? WHERE request_id=?",
            ('{"character_id":"hero","capacity":20,"max_stack":99,'
             '"revision":1,"items":[["potion",NaN]]}', "tampered-float"),
        )
        with self.assertRaisesRegex(InventoryStoreError, "non-finite"):
            self.store.apply("hero", "tampered-float", 0, [("potion", 1)])


if __name__ == "__main__":
    unittest.main()
