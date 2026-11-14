"""Session ownership tests for synthetic durable map positions only."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_map_position_service import (
    SqliteAuthorizedMapPositionService,
)
from server.sqlite_map_position_store import MapPositionAlreadyExists
from server.sqlite_session_store import SqliteSessionStore
from server.synthetic_map_position import MapPosition, Position


class SqliteAuthorizedMapPositionServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-map.sqlite3")
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.addCleanup(self.db.close)
        self.db.execute(
            """CREATE TABLE characters (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL
            )"""
        )
        self.db.executemany(
            "INSERT INTO characters(id, account_id) VALUES (?, ?)",
            ((101, 1), (202, 2)),
        )
        self.db.commit()
        self.now = [2000.0]
        self.service = SqliteAuthorizedMapPositionService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_create_enter_move_leave_and_read_position(self):
        self.assertEqual(
            self.service.create_position(self.owner_token, 101), MapPosition()
        )
        entered = self.service.enter_map(
            self.owner_token, 101, "enter-1", 0, 7, 10, 20
        )
        self.assertFalse(entered.replayed)
        self.assertEqual(
            entered.snapshot, MapPosition(7, Position(10, 20), 1)
        )

        moved = self.service.move(
            self.owner_token, 101, "move-1", 1, 7, 12, 22
        )
        self.assertEqual(
            moved.snapshot, MapPosition(7, Position(12, 22), 2)
        )
        left = self.service.leave_map(
            self.owner_token, 101, "leave-1", 2, 7
        )
        self.assertEqual(left.snapshot, MapPosition(revision=3))
        self.assertEqual(
            self.service.get_position(self.owner_token, 101),
            MapPosition(revision=3),
        )
        self.assertEqual(
            self.service.positions.verify_integrity(),
            {"snapshots": 1, "mutations": 3},
        )

    def test_foreign_account_cannot_create_read_or_mutate_position(self):
        self.service.create_position(self.owner_token, 101)
        self.service.enter_map(
            self.owner_token, 101, "owner-enter", 0, 7, 1, 2
        )
        attempts = (
            lambda: self.service.create_position(self.other_token, 101),
            lambda: self.service.get_position(self.other_token, 101),
            lambda: self.service.enter_map(
                self.other_token, 101, "foreign-enter", 1, 7, 2, 3
            ),
            lambda: self.service.move(
                self.other_token, 101, "foreign-move", 1, 7, 2, 3
            ),
            lambda: self.service.leave_map(
                self.other_token, 101, "foreign-leave", 1, 7
            ),
        )
        for attempt in attempts:
            with self.subTest(attempt=attempt), self.assertRaises(SessionError):
                attempt()
        self.assertEqual(
            self.service.get_position(self.owner_token, 101),
            MapPosition(7, Position(1, 2), 1),
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations"
            ).fetchone()[0],
            1,
        )

    def test_unknown_and_foreign_character_have_same_error(self):
        messages = []
        for character_id in (202, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.get_position(self.owner_token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])

    def test_expired_and_revoked_sessions_cannot_access_position(self):
        self.service.create_position(self.owner_token, 101)
        self.now[0] = 2030.0
        with self.assertRaises(SessionError):
            self.service.get_position(self.owner_token, 101)

        self.now[0] = 2000.0
        revoked_token = self.service.sessions.issue(1)
        self.assertTrue(self.service.sessions.revoke(revoked_token))
        with self.assertRaises(SessionError):
            self.service.enter_map(
                revoked_token, 101, "revoked-enter", 0, 7, 1, 1
            )
        self.assertEqual(
            self.service.positions.get("101"), MapPosition(revision=0)
        )

    def test_invalid_character_ids_fail_closed(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.create_position(self.owner_token, value)

    def test_idempotent_replay_is_still_ownership_checked(self):
        self.service.create_position(self.owner_token, 101)
        first = self.service.enter_map(
            self.owner_token, 101, "same-enter", 0, 7, 10, 20
        )
        self.service.move(
            self.owner_token, 101, "later-move", 1, 7, 11, 20
        )
        replay = self.service.enter_map(
            self.owner_token, 101, "same-enter", 0, 7, 10, 20
        )
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        with self.assertRaises(SessionError):
            self.service.enter_map(
                self.other_token, 101, "same-enter", 0, 7, 10, 20
            )
        self.assertEqual(
            self.service.get_position(self.owner_token, 101),
            MapPosition(7, Position(11, 20), 2),
        )

    def test_duplicate_position_creation_is_rejected(self):
        self.service.create_position(self.owner_token, 101)
        with self.assertRaises(MapPositionAlreadyExists):
            self.service.create_position(self.owner_token, 101)

    def test_service_requires_existing_ownership_schema_without_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedMapPositionService(db)
        tables = {
            row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertNotIn("durable_sessions", tables)
        self.assertNotIn("map_position_snapshots", tables)

    def test_session_revocation_serializes_with_map_transition(self):
        self.service.create_position(self.owner_token, 101)
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_enter = self.service.positions.enter

        def paused_enter(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release map-position transition")
            return original_enter(*args, **kwargs)

        self.service.positions.enter = paused_enter

        def mutate():
            try:
                outcome["mutation"] = self.service.enter_map(
                    self.owner_token, 101, "atomic-revoke-map", 0, 7, 1, 2
                )
            except BaseException as exc:
                outcome["mutation_error"] = exc

        def revoke():
            connection = sqlite3.connect(
                self.path, timeout=10, isolation_level=None
            )
            try:
                sessions = SqliteSessionStore(
                    connection, ttl_seconds=30, clock=lambda: self.now[0]
                )
                revoke_started.set()
                outcome["revoked"] = sessions.revoke(self.owner_token)
            except BaseException as exc:
                outcome["revoke_error"] = exc
            finally:
                connection.close()
                revoke_done.set()

        mutation_thread = threading.Thread(target=mutate)
        revoke_thread = threading.Thread(target=revoke)
        mutation_thread.start()
        self.assertTrue(entered.wait(5))
        revoke_thread.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(revoke_done.wait(0.2))
        finally:
            release.set()
        mutation_thread.join(5)
        revoke_thread.join(5)
        self.assertFalse(mutation_thread.is_alive())
        self.assertFalse(revoke_thread.is_alive())
        self.assertNotIn("mutation_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertTrue(outcome["revoked"])
        self.assertEqual(
            outcome["mutation"].snapshot,
            MapPosition(7, Position(1, 2), 1),
        )
        with self.assertRaises(SessionError):
            self.service.get_position(self.owner_token, 101)


if __name__ == "__main__":
    unittest.main()
