"""Authorized map-capacity integration tests; all IDs and limits are synthetic."""
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from server.sqlite_authorized_map_service import SqliteAuthorizedMapService
from server.sqlite_map_capacity_store import MapCapacityExceeded
from server.sessions import SessionError
from server.synthetic_map_position import MapPosition, Position


class SqliteAuthorizedMapCapacityServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-map-capacity.sqlite3")
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.addCleanup(self.db.close)
        self.db.execute(
            "CREATE TABLE characters (id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL)"
        )
        self.db.executemany(
            "INSERT INTO characters(id, account_id) VALUES (?, ?)",
            ((101, 1), (202, 2)),
        )
        self.now = [1000.0]
        self.service = SqliteAuthorizedMapService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0],
            map_capacities={7: 1},
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)
        self.service.create_position(self.owner_token, 101)
        self.service.create_position(self.other_token, 202)

    def test_capacity_rejection_rolls_back_position_and_receipt(self):
        entered = self.service.enter(
            self.owner_token, 101, "first-enter", 0, 7, 1, 2
        )
        self.assertEqual(entered.snapshot, MapPosition(7, Position(1, 2), 1))
        with self.assertRaises(MapCapacityExceeded):
            self.service.enter(
                self.other_token, 202, "second-enter", 0, 7, 3, 4
            )
        self.assertEqual(
            self.service.get_position(self.other_token, 202), MapPosition()
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations WHERE request_id=?",
                ("second-enter",),
            ).fetchone()[0],
            0,
        )
        self.assertEqual(self.service.capacities.members(7), frozenset({"101"}))

    def test_leave_releases_slot_for_another_character(self):
        self.service.enter(self.owner_token, 101, "enter-a", 0, 7, 0, 0)
        self.service.leave(self.owner_token, 101, "leave-a", 1, 7)
        self.assertFalse(self.service.capacities.members(7))
        result = self.service.enter(
            self.other_token, 202, "enter-b", 0, 7, 5, 6
        )
        self.assertEqual(result.snapshot, MapPosition(7, Position(5, 6), 1))
        self.assertEqual(self.service.capacities.members(7), frozenset({"202"}))

    def test_replayed_old_enter_does_not_resurrect_occupancy(self):
        first = self.service.enter(
            self.owner_token, 101, "replay-enter", 0, 7, 2, 3
        )
        self.service.leave(self.owner_token, 101, "replay-leave", 1, 7)
        replay = self.service.enter(
            self.owner_token, 101, "replay-enter", 0, 7, 2, 3
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        self.assertEqual(self.service.get_position(self.owner_token, 101), MapPosition(revision=2))
        self.assertFalse(self.service.capacities.members(7))

    def test_two_service_connections_share_one_durable_capacity(self):
        barrier = threading.Barrier(2)

        def enter(token, character_id, request_id):
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                service = SqliteAuthorizedMapService(
                    connection, ttl_seconds=30, clock=lambda: self.now[0]
                )
                barrier.wait(timeout=5)
                try:
                    service.enter(
                        token, character_id, request_id, 0, 7, 10, 20
                    )
                    return "accepted"
                except MapCapacityExceeded:
                    return "full"
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(
                lambda args: enter(*args),
                (
                    (self.owner_token, 101, "concurrent-a"),
                    (self.other_token, 202, "concurrent-b"),
                ),
            ))
        self.assertCountEqual(outcomes, ["accepted", "full"])
        self.assertEqual(len(self.service.capacities.members(7)), 1)
        self.assertEqual(
            sum(
                self.service.get_position(token, character_id).map_id == 7
                for token, character_id in (
                    (self.owner_token, 101), (self.other_token, 202)
                )
            ),
            1,
        )

    def test_startup_capacity_configuration_is_atomic(self):
        with self.assertRaises(ValueError):
            SqliteAuthorizedMapService(
                self.db, ttl_seconds=30, clock=lambda: self.now[0],
                map_capacities={8: 2, -1: 3},
            )
        self.assertIsNone(self.service.capacities.capacity(8))

    def test_expired_session_fails_before_capacity_change(self):
        self.now[0] = 1030.0
        with self.assertRaises(SessionError):
            self.service.enter(
                self.owner_token, 101, "expired-enter", 0, 7, 0, 0
            )
        self.assertFalse(self.service.capacities.members(7))

    def test_foreign_character_cannot_claim_capacity(self):
        with self.assertRaises(SessionError):
            self.service.enter(
                self.owner_token, 202, "foreign-enter", 0, 7, 0, 0
            )
        self.assertEqual(
            self.service.get_position(self.other_token, 202), MapPosition()
        )
        self.assertFalse(self.service.capacities.members(7))
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations WHERE request_id=?",
                ("foreign-enter",),
            ).fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
