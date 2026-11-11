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
    AuthorizedWorldMutationSnapshot,
    AuthorizedWorldSnapshot,
    SqliteAuthorizedWorldStateService,
)
from server.sqlite_map_position_store import (
    MapPositionNotFound,
    MapPositionRevisionConflict,
)
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

    @property
    def character_id(self):
        return self.bootstrap.character.character_id

    def test_owner_reads_all_three_snapshots_consistently(self):
        result = self.service.get_snapshot(
            self.owner_token, self.character_id
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
        self.service.get_snapshot(self.owner_token, self.character_id)
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
            (self.other_token, self.character_id),
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
        self.db.execute(
            "DELETE FROM map_position_snapshots WHERE character_id=?",
            (str(self.character_id),),
        )
        self.db.commit()
        with self.assertRaises(MapPositionNotFound):
            self.service.get_snapshot(self.owner_token, self.character_id)
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_snapshots WHERE character_id=?",
                (str(self.character_id),),
            ).fetchone()[0],
            0,
        )

    def test_expired_and_revoked_sessions_cannot_read(self):
        self.now[0] = 10_030.0
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, self.character_id)

        self.now[0] = 10_000.0
        token = self.service.sessions.issue(1)
        self.assertTrue(self.service.sessions.revoke(token))
        with self.assertRaises(SessionError):
            self.service.get_snapshot(token, self.character_id)

    def test_enter_and_move_return_the_world_snapshot_from_the_same_commit(self):
        entered = self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "enter-1", 0, 7, 10, 20
        )
        expected_entered = MapPosition(7, Position(10, 20), 1)
        self.assertIsInstance(entered, AuthorizedWorldMutationSnapshot)
        self.assertFalse(entered.mutation.replayed)
        self.assertEqual(entered.mutation.snapshot, expected_entered)
        self.assertEqual(entered.snapshot.map_position, expected_entered)
        self.assertEqual(entered.snapshot.player_state.level, 4)

        moved = self.service.move_and_get_snapshot(
            self.owner_token, self.character_id, "move-1", 1, 7, 13, 24
        )
        expected_moved = MapPosition(7, Position(13, 24), 2)
        self.assertFalse(moved.mutation.replayed)
        self.assertEqual(moved.mutation.snapshot, expected_moved)
        self.assertEqual(moved.snapshot.map_position, expected_moved)
        self.assertEqual(
            self.service.get_snapshot(
                self.owner_token, self.character_id
            ).map_position,
            expected_moved,
        )

    def test_idempotent_retry_returns_original_receipt_and_current_snapshot(self):
        self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "enter", 0, 9, 0, 0
        )
        first = self.service.move_and_get_snapshot(
            self.owner_token, self.character_id, "move-first", 1, 9, 2, 3
        )
        self.service.move_and_get_snapshot(
            self.owner_token, self.character_id, "move-second", 2, 9, 5, 8
        )

        replay = self.service.move_and_get_snapshot(
            self.owner_token, self.character_id, "move-first", 1, 9, 2, 3
        )
        self.assertTrue(replay.mutation.replayed)
        self.assertEqual(replay.mutation.snapshot, first.mutation.snapshot)
        self.assertEqual(
            replay.snapshot.map_position,
            MapPosition(9, Position(5, 8), 3),
        )

    def test_stale_move_rolls_back_without_adding_a_receipt(self):
        self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "enter", 0, 4, 1, 1
        )
        before_count = self.db.execute(
            "SELECT count(*) FROM map_position_mutations"
        ).fetchone()[0]
        with self.assertRaises(MapPositionRevisionConflict):
            self.service.move_and_get_snapshot(
                self.owner_token, self.character_id, "stale-move",
                0, 4, 2, 2,
            )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations"
            ).fetchone()[0],
            before_count,
        )
        self.assertEqual(
            self.service.get_snapshot(
                self.owner_token, self.character_id
            ).map_position,
            MapPosition(4, Position(1, 1), 1),
        )

    def test_foreign_account_cannot_transition_map(self):
        self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "owner-enter", 0, 4, 1, 1
        )
        with self.assertRaises(SessionError):
            self.service.move_and_get_snapshot(
                self.other_token, self.character_id, "foreign-move",
                1, 4, 2, 2,
            )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations"
            ).fetchone()[0],
            1,
        )

    def test_session_revocation_serializes_with_move_and_snapshot(self):
        self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "before-move", 0, 3, 0, 0
        )
        entered = threading.Event()
        release = threading.Event()
        revoke_started = threading.Event()
        revoke_done = threading.Event()
        outcome = {}
        original_move = self.service.positions.move

        def paused_move(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test did not release atomic world move")
            return original_move(*args, **kwargs)

        self.service.positions.move = paused_move

        def move():
            try:
                outcome["result"] = self.service.move_and_get_snapshot(
                    self.owner_token, self.character_id, "atomic-move",
                    1, 3, 6, 7,
                )
            except BaseException as exc:
                outcome["move_error"] = exc

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

        mover = threading.Thread(target=move)
        revoker = threading.Thread(target=revoke)
        mover.start()
        self.assertTrue(entered.wait(5))
        revoker.start()
        self.assertTrue(revoke_started.wait(5))
        try:
            self.assertFalse(
                revoke_done.wait(0.2),
                "revocation must wait for the atomic movement transaction",
            )
        finally:
            release.set()
        mover.join(5)
        revoker.join(5)

        self.assertFalse(mover.is_alive())
        self.assertFalse(revoker.is_alive())
        self.assertNotIn("move_error", outcome)
        self.assertNotIn("revoke_error", outcome)
        self.assertTrue(outcome["revoked"])
        self.assertEqual(
            outcome["result"].snapshot.map_position,
            MapPosition(3, Position(6, 7), 2),
        )
        with self.assertRaises(SessionError):
            self.service.get_snapshot(self.owner_token, self.character_id)


    def test_leave_returns_unplaced_snapshot_and_replay_keeps_current_world_view(self):
        self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "enter-before-leave",
            0, 11, 4, 5,
        )
        self.service.move_and_get_snapshot(
            self.owner_token, self.character_id, "move-before-leave",
            1, 11, 8, 9,
        )

        left = self.service.leave_and_get_snapshot(
            self.owner_token, self.character_id, "leave-1", 2, 11
        )
        unplaced = MapPosition(revision=3)
        self.assertFalse(left.mutation.replayed)
        self.assertEqual(left.mutation.snapshot, unplaced)
        self.assertEqual(left.snapshot.map_position, unplaced)
        self.assertEqual(left.snapshot.character, self.bootstrap.character)
        self.assertEqual(left.snapshot.player_state,
                         PlayerSnapshot("1", 4, 125, 0, 0))

        reentered = self.service.enter_and_get_snapshot(
            self.owner_token, self.character_id, "reenter-after-leave",
            3, 12, -2, 6,
        )
        replay = self.service.leave_and_get_snapshot(
            self.owner_token, self.character_id, "leave-1", 2, 11
        )
        self.assertTrue(replay.mutation.replayed)
        self.assertEqual(replay.mutation.snapshot, unplaced)
        self.assertEqual(replay.snapshot.map_position,
                         reentered.snapshot.map_position)
        self.assertEqual(replay.snapshot.map_position,
                         MapPosition(12, Position(-2, 6), 4))

    def test_snapshot_read_failure_rolls_back_map_transition_and_receipt(self):
        self.db.execute(
            "DELETE FROM player_state_snapshots WHERE character_id=?",
            (str(self.character_id),),
        )
        self.db.commit()
        before_receipts = self.db.execute(
            "SELECT count(*) FROM map_position_mutations"
        ).fetchone()[0]

        with self.assertRaises(PlayerNotFound):
            self.service.enter_and_get_snapshot(
                self.owner_token, self.character_id, "rollback-enter",
                0, 5, 3, 4,
            )

        self.assertEqual(
            self.service.positions.get(str(self.bootstrap.character.character_id)),
            MapPosition(),
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations"
            ).fetchone()[0],
            before_receipts,
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM map_position_mutations "
                "WHERE request_id='rollback-enter'"
            ).fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
