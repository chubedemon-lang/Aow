"""Focused regression coverage for one-clock durable-session integrity audits."""

import sqlite3
import unittest

from server.sqlite_session_store import SqliteSessionStore


class SessionIntegrityClockSnapshotTests(unittest.TestCase):
    def test_integrity_audit_samples_clock_once_for_all_rows(self):
        now = [1_000.0]
        clock_calls = []

        def clock():
            clock_calls.append(now[0])
            return now[0]

        connection = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(connection.close)
        store = SqliteSessionStore(connection, ttl_seconds=60, clock=clock)

        store.issue(501, ttl_seconds=1)
        store.issue(502, ttl_seconds=30)
        now[0] = 1_001.0
        clock_calls.clear()

        report = store.verify_integrity()

        self.assertEqual(clock_calls, [1_001.0])
        self.assertEqual(
            report,
            {
                "session_count": 2,
                "active_session_count": 1,
                "expired_session_count": 1,
            },
        )
        self.assertEqual(
            connection.execute(
                "SELECT count(*) FROM durable_sessions"
            ).fetchone()[0],
            2,
        )
        self.assertFalse(connection.in_transaction)


if __name__ == "__main__":
    unittest.main()
