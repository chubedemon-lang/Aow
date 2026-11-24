"""Consistent-snapshot regressions for durable synthetic map-capacity audits."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sqlite_map_capacity_store import (
    MapCapacityStoreError,
    SqliteMapCapacityStore,
)
from server.sqlite_map_position_store import SqliteMapPositionStore


class SqliteMapCapacityAuditSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "map-capacity.sqlite3")
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None
        )
        self.addCleanup(self.db.close)
        self.positions = SqliteMapPositionStore(self.db)
        self.capacity = SqliteMapCapacityStore(self.db)
        self.positions.create("alpha")
        self.capacity.configure_map(7, 1)
        self.positions.enter("alpha", "enter-alpha", 0, 7, 1, 2)
        self.capacity.reconcile("alpha", 7)

    def test_integrity_audit_pins_snapshot_before_quick_check(self):
        audit_at_quick_check = threading.Event()
        writer_update_started = threading.Event()
        writer_done = threading.Event()
        writer_errors = []
        observations = {}

        def audit_trace(statement):
            if statement.strip().casefold() == "pragma quick_check":
                audit_at_quick_check.set()
                if not writer_update_started.wait(5):
                    observations["writer_reached_update"] = False
                    return
                observations["writer_reached_update"] = True
                observations["writer_blocked_by_snapshot"] = not writer_done.wait(0.25)

        self.db.set_trace_callback(audit_trace)

        def concurrent_writer():
            if not audit_at_quick_check.wait(5):
                writer_errors.append(TimeoutError("audit did not reach quick_check"))
                return
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                def writer_trace(statement):
                    if statement.lstrip().casefold().startswith(
                        "update map_position_snapshots"
                    ):
                        writer_update_started.set()

                connection.set_trace_callback(writer_trace)
                connection.execute(
                    "UPDATE map_position_snapshots SET map_id=? WHERE character_id=?",
                    (8, "alpha"),
                )
                connection.commit()
            except BaseException as exc:
                writer_errors.append(exc)
            finally:
                connection.close()
                writer_done.set()

        writer = threading.Thread(target=concurrent_writer)
        writer.start()
        try:
            report = self.capacity.verify_integrity()
        finally:
            self.db.set_trace_callback(None)
            writer.join(10)

        self.assertFalse(writer.is_alive(), "concurrent writer did not finish")
        self.assertEqual(writer_errors, [])
        self.assertTrue(observations.get("writer_reached_update"))
        self.assertTrue(
            observations.get("writer_blocked_by_snapshot"),
            "a writer committed between the audit snapshot and its projection reads",
        )
        self.assertEqual(report, {"members": 1, "configured_maps": 1})
        self.assertFalse(self.db.in_transaction)

        # The concurrent write is allowed after the read-only audit releases
        # its snapshot; a later audit must then detect the deliberate drift.
        with self.assertRaises(MapCapacityStoreError):
            self.capacity.verify_integrity()
        self.assertFalse(self.db.in_transaction)


if __name__ == "__main__":
    unittest.main()
