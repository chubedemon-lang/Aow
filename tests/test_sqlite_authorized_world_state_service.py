"""Consistent session-authorized synthetic character/player/map reads."""
import os
import sqlite3
import tempfile
import threading
import unittest

from server.sessions import SessionError
from server.sqlite_authorized_character_service import (
    SqliteAuthorizedCharacterService,
)
from server.sqlite_authorized_world_state_service import (
    AuthorizedWorldSnapshot,
    SqliteAuthorizedWorldStateService,
)
from server.sqlite_map_position_store import MapPositionNotFound
from server.sqlite_player_state_store import PlayerNotFound, PlayerSnapshot
from server.sqlite_session_store import SqliteSessionStore
from server.synthetic_map_position import MapPosition, Position


class SqliteAuthorizedWorldStateServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = os.path.join(self.temp.name, "world-state.sqlite3")
        self.db = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(
            """CREATE TABLE accounts (
                   id INTEGER PRIMARY KEY,
                   username TEXT NOT NULL UNIQUE
               );
               CREATE TABLE characters (
                   id INTEGER PRIMARY KEY,
                   account_id INTEGER NOT NULL UNIQUE,
                   name TEXT NOT NULL,
                   map_id TEXT NOT NULL,
                   x INTEGER NOT NULL,
                   y INTEGER NOT NULL,
                   FOREIGN KEY(account_id) REFERENCES accounts(id)
               );
               CREATE TABLE wallets (
                   character_id INTEGER PRIMARY KEY,
                   balance INTEGER NOT NULL CHECK(balance >= 0),
                   FOREIGN KEY(character_id) REFERENCES characters(id)
               );
               INSERT INTO accounts(id, username) VALUES (1, 'alice'), (2, 'bob');"""
        )
        self.now = [10_000.0]
        self.characters = SqliteAuthorizedCharacterService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )
        self.owner_token = self.characters.sessions.issue(1)
        self.other_token = self.characters.sessions.issue(2)
        self.bootstrap = self.characters.create_with_initial_state(
            self.owner_token, "Alice", level=4, experience=125
        )
        self.service = SqliteAuthorizedWorldStateService(
            self.db, ttl_seconds=30, clock=lambda: self.now[0]
        )

    def test_owner_reads_all_three_snapshots_consistently(self):
        result = self.service.get_snapshot(
            self.owner_token, self.bootstrap.character.character_id
        )
        self.assertEqual(
            result,
            AuthorizedWorldSnapshot(
                character=self.bootstrap.character,
                player_state=PlayerSnapshot("1", 4, 125, 0, 0),
                map_position=MapPosition(),
            ),
        )

    def test_read_does_not_create_or_mutate_domain_state(self):
        before = {
            table: self.db.execute(
                "SELECT count(*) FROM " + table
            ).fetchone()[0]
            for table in (
                "characters",
                "wallets",
                "player_state_snapshots",
                "player_state_mutations",
                "map_position_snapshots",
                "map_position_mutations",
            )
        }
        self.service.get_snapshot(
            self.owner_token, self.bootstrap.character.character_id
        )
        after = {
            table: self.db.execute(
                "SELECT count(*) FROM " + table
            ).fetchone()[0]
            for table in before
        }
        self.assertEqual(after, before)

    def test_foreign_and_unknown_characters_share_same_error(self):
        messages = []
        for token, character_id in (
            (self.other_token, self.bootstrap.character.character_id),
            (self.owner_token, 999),
        ):
            with self.assertRaises(SessionError) as caught:
                self.service.get_snapshot(token, character_id)
            messages.append(str(caught.exception))
        self.assertEqual(messages[0], messages[1])

    def test_missing_player_snapshot_fails_closed(self):
        created = self.characters.create(self.other_token, "Bob")
        with self.assertRaises(PlayerNotFound):
            self.service.get_snapshot(self.other_token, created.character_id)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM characters WHERE id=?",
                (created.character_id,),
            ).fetchone()[0],
            1,
        )

    def test_missing_map_snapshot_fails_closed_without_repair(self):
        character_id = self.bootstrap.character.character_id
        self.db.execute(
            "DELETE FROM map_position_snapshots WHERE character_id=?",
            (str(character_id),),
        )
        self.db.commit()
        with self.assertRaises(MapPositionNotFound):
            self.service.get_snapshot(self.owner_token, character_id)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_snapshots WHERE character_id=?",
                (str(character_id),),
            ).fetchone()[0],
            0,
        )

    def test_expired_and_revoked_sessions_cannot_read(self):
        character_id = self.bootstrap.character.character_id
        self.now[0] = 10_030.0
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, character_id)

        self.now[0] = 10_000.0
        token = self.service.sessions.issue(1)
        self.assertTrue(self.service.sessions.revoke(token))
        with self.assertRaises(SessionError):
            self.service.get_snapshot(token, character_id)

    def test_session_revocation_serializes_with_world_snapshot_read(self):
        character_id = self.bootstrap.character.character_id
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_get = self.service.players.get

        def paused_get(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release world snapshot read")
            return original_get(*args, **kwargs)

        self.service.players.get = paused_get

        def read_snapshot():
            try:
                outcome["snapshot"] = self.service.get_snapshot(
                    self.owner_token, character_id
                )
            except BaseException as exc:
                outcome["read_error"] = exc

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

        reader = threading.Thread(target=read_snapshot)
        revoker = threading.Thread(target=revoke)
        reader.start()
        self.assertTrue(entered.wait(5))
        revoker.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(revoke_done.wait(0.2))
        finally:
            release.set()
        reader.join(5)
        revoker.join(5)

        self.assertFalse(reader.is_alive())
        self.assertFalse(revoker.is_alive())
        self.assertNotIn("read_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertIsInstance(outcome["snapshot"], AuthorizedWorldSnapshot)
        self.assertTrue(outcome["revoked"])
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, character_id)


if __name__ == "__main__":
    unittest.main()
