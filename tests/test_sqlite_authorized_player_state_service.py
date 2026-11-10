"""Session ownership tests for synthetic durable player state only."""
import os
import sqlite3
import threading
import tempfile
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_player_state_service import (
    SqliteAuthorizedPlayerStateService,
)
from server.sqlite_player_state_store import PlayerAlreadyExists, PlayerSnapshot

from server.sqlite_session_store import SqliteSessionStore


class SqliteAuthorizedPlayerStateServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "authorized-player.sqlite3")
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
        self.now = [2000.0]
        self.service = SqliteAuthorizedPlayerStateService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.service.sessions.issue(1)
        self.other_token = self.service.sessions.issue(2)

    def test_owner_can_create_read_and_mutate_player_snapshot(self):
        created = self.service.create_snapshot(
            self.owner_token, 101, level=3, experience=20, currency=75
        )
        self.assertEqual(created, PlayerSnapshot("101", 3, 20, 75, 0))
        changed = self.service.apply(
            self.owner_token, 101, "award-1", 0,
            level=4, experience_delta=30, currency_delta=-5,
        )
        self.assertFalse(changed.replayed)
        self.assertEqual(changed.snapshot, PlayerSnapshot("101", 4, 50, 70, 1))
        self.assertEqual(
            self.service.get_snapshot(self.owner_token, 101),
            changed.snapshot,
        )

    def test_foreign_account_cannot_create_read_or_mutate(self):
        self.service.create_snapshot(self.owner_token, 101, currency=50)
        attempts = (
            lambda: self.service.create_snapshot(self.other_token, 101),
            lambda: self.service.get_snapshot(self.other_token, 101),
            lambda: self.service.apply(
                self.other_token, 101, "foreign-award", 0,
                currency_delta=10,
            ),
        )
        for attempt in attempts:
            with self.subTest(attempt=attempt), self.assertRaises(SessionError):
                attempt()
        self.assertEqual(
            self.service.get_snapshot(self.owner_token, 101),
            PlayerSnapshot("101", 1, 0, 50, 0),
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM player_state_mutations"
            ).fetchone()[0],
            0,
        )

    def test_unknown_and_foreign_character_have_same_error(self):
        messages = []
        for character_id in (202, 999):
            with self.assertRaises(SessionError) as caught:
                self.service.get_snapshot(self.owner_token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])

    def test_expired_session_cannot_read_or_mutate(self):
        self.service.create_snapshot(self.owner_token, 101)
        self.now[0] = 2030.0
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, 101)
        with self.assertRaises(SessionError):
            self.service.apply(
                self.owner_token, 101, "expired", 0, experience_delta=1
            )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM player_state_mutations"
            ).fetchone()[0],
            0,
        )

    def test_revoked_session_cannot_read_or_mutate(self):
        self.service.create_snapshot(self.owner_token, 101)
        self.assertTrue(self.service.sessions.revoke(self.owner_token))
        self.assertFalse(self.service.sessions.revoke(self.owner_token))
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, 101)
        with self.assertRaises(SessionError):
            self.service.apply(
                self.owner_token, 101, "revoked", 0, experience_delta=1
            )

    def test_invalid_character_ids_fail_closed(self):
        for value in (True, 0, -1, "101", None):
            with self.subTest(value=value), self.assertRaises(SessionError):
                self.service.create_snapshot(self.owner_token, value)

    def test_idempotent_replay_is_still_ownership_checked(self):
        self.service.create_snapshot(self.owner_token, 101, currency=100)
        first = self.service.apply(
            self.owner_token, 101, "same-award", 0, currency_delta=-10
        )
        self.service.apply(
            self.owner_token, 101, "later-award", 1, currency_delta=5
        )
        replay = self.service.apply(
            self.owner_token, 101, "same-award", 0, currency_delta=-10
        )
        self.assertFalse(first.replayed)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, first.snapshot)
        with self.assertRaises(SessionError):
            self.service.apply(
                self.other_token, 101, "same-award", 0, currency_delta=-10
            )
        self.assertEqual(self.service.get_snapshot(self.owner_token, 101).currency, 95)

    def test_duplicate_snapshot_creation_is_rejected(self):
        self.service.create_snapshot(self.owner_token, 101)
        with self.assertRaises(PlayerAlreadyExists):
            self.service.create_snapshot(self.owner_token, 101)

    def test_service_requires_existing_ownership_schema_without_side_effects(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        with self.assertRaisesRegex(ValueError, "characters"):
            SqliteAuthorizedPlayerStateService(db)
        self.assertEqual(
            db.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='durable_sessions'"
            ).fetchone()[0],
            0,
        )



    def test_session_revocation_serializes_with_player_state_mutation(self):
        self.service.create_snapshot(self.owner_token, 101, currency=10)
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_apply = self.service.players.apply

        def paused_apply(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release player-state mutation")
            return original_apply(*args, **kwargs)

        self.service.players.apply = paused_apply

        def mutate():
            try:
                outcome["mutation"] = self.service.apply(
                    self.owner_token, 101, "atomic-revoke-player",
                    0, experience_delta=5,
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
        self.assertEqual(outcome["mutation"].snapshot.experience, 5)
        self.assertEqual(self.service.players.get("101").experience, 5)
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, 101)


if __name__ == "__main__":
    unittest.main()
