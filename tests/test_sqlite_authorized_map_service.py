"""Session ownership gate tests use only synthetic local SQLite records."""
import os
import sqlite3
import threading
import tempfile
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_map_service import SqliteAuthorizedMapService
from server.sqlite_map_position_store import MapPositionAlreadyExists
from server.synthetic_map_position import MapPosition, Position

from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedMapServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-map.sqlite3")
        self.db = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
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
        self.now = [1000.0]
        self.service = SqliteAuthorizedMapService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_create_enter_move_leave_and_read(self):
        self.assertEqual(
            self.service.create_position(self.owner_token, 101),
            MapPosition(),
        )
        entered = self.service.enter(
            self.owner_token, 101, "enter-1", 0, 7, 10, -4
        )
        self.assertEqual(entered.snapshot,
                         MapPosition(7, Position(10, -4), 1))
        moved = self.service.move(
            self.owner_token, 101, "move-1", 1, 7, 12, -3
        )
        self.assertEqual(moved.snapshot,
                         MapPosition(7, Position(12, -3), 2))
        left = self.service.leave(
            self.owner_token, 101, "leave-1", 2, 7
        )
        self.assertEqual(left.snapshot, MapPosition(revision=3))
        self.assertEqual(
            self.service.get_position(self.owner_token, 101),
            left.snapshot,
        )

    def test_other_account_cannot_read_or_mutate_owned_character(self):
        self.service.create_position(self.owner_token, 101)
        self.service.enter(self.owner_token, 101, "owner-enter", 0, 1, 0, 0)
        attempts = (
            lambda: self.service.get_position(self.other_token, 101),
            lambda: self.service.create_position(self.other_token, 101),
            lambda: self.service.enter(
                self.other_token, 101, "foreign-enter", 1, 1, 1, 1
            ),
            lambda: self.service.move(
                self.other_token, 101, "foreign-move", 1, 1, 1, 1
            ),
            lambda: self.service.leave(
                self.other_token, 101, "foreign-leave", 1, 1
            ),
        )
        for attempt in attempts:
            with self.subTest(attempt=attempt), self.assertRaises(SessionError):
                attempt()
        self.assertEqual(
            self.service.get_position(self.owner_token, 101),
            MapPosition(1, Position(0, 0), 1),
        )

    def test_unknown_and_foreign_character_have_same_authorization_error(self):
        messages = []
        for character_id in (202, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.get_position(self.owner_token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])

    def test_expired_session_cannot_read_or_mutate(self):
        self.service.create_position(self.owner_token, 101)
        self.now[0] = 1030.0
        with self.assertRaises(SessionError):
            self.service.get_position(self.owner_token, 101)
        with self.assertRaises(SessionError):
            self.service.enter(self.owner_token, 101, "expired", 0, 1, 0, 0)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations"
            ).fetchone()[0],
            0,
        )

    def test_revoked_session_cannot_read_or_mutate(self):
        self.service.create_position(self.owner_token, 101)
        self.assertTrue(self.service.sessions.revoke(self.owner_token))
        self.assertFalse(self.service.sessions.revoke(self.owner_token))
        with self.assertRaises(SessionError):
            self.service.get_position(self.owner_token, 101)
        with self.assertRaises(SessionError):
            self.service.move(self.owner_token, 101, "revoked", 0, 1, 1, 1)

    def test_invalid_character_ids_fail_closed(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.create_position(self.owner_token, value)

    def test_idempotent_retry_is_authorized_each_time(self):
        self.service.create_position(self.owner_token, 101)
        first = self.service.enter(
            self.owner_token, 101, "retry", 0, 3, 4, 5
        )
        self.service.move(
            self.owner_token, 101, "next", 1, 3, 6, 7
        )
        replay = self.service.enter(
            self.owner_token, 101, "retry", 0, 3, 4, 5
        )
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        with self.assertRaises(SessionError):
            self.service.enter(
                self.other_token, 101, "retry", 0, 3, 4, 5
            )

    def test_duplicate_position_creation_is_not_silently_accepted(self):
        self.service.create_position(self.owner_token, 101)
        with self.assertRaises(MapPositionAlreadyExists):
            self.service.create_position(self.owner_token, 101)

    def test_service_requires_existing_ownership_schema_without_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedMapService(db)
        self.assertEqual(
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='durable_sessions'"
            ).fetchone()[0],
            0,
        )



    def test_session_revocation_serializes_with_map_movement(self):
        self.service.create_position(self.owner_token, 101)
        self.service.enter(self.owner_token, 101, "before-move", 0, 1, 0, 0)
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_move = self.service.positions.move

        def paused_move(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release map movement")
            return original_move(*args, **kwargs)

        self.service.positions.move = paused_move

        def move():
            try:
                outcome["mutation"] = self.service.move(
                    self.owner_token, 101, "atomic-revoke-move",
                    1, 1, 2, 3,
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

        mutation_thread = threading.Thread(target=move)
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
        self.assertEqual(outcome["mutation"].snapshot, MapPosition(1, Position(2, 3), 2))
        self.assertEqual(self.service.positions.get("101"), MapPosition(1, Position(2, 3), 2))
        with self.assertRaises(SessionError):
            self.service.get_position(self.owner_token, 101)


if __name__ == "__main__":
    unittest.main()
