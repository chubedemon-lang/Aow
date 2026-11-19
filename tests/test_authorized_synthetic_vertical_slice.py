"""Synthetic cross-service lifecycle integration; not an AOW wire test."""
import os
import sqlite3
import tempfile
import unittest

from server.combat import Battle, Fighter
from server.sessions import SessionError
from server.sqlite_authorized_combat_service import SqliteAuthorizedCombatService
from server.sqlite_account_auth_service import SqliteAccountAuthService
from server.sqlite_authorized_character_service import SqliteAuthorizedCharacterService
from server.sqlite_authorized_inventory_service import SqliteAuthorizedInventoryService
from server.sqlite_authorized_player_state_service import SqliteAuthorizedPlayerStateService
from server.sqlite_authorized_map_service import SqliteAuthorizedMapService
from server.sqlite_authorized_shop_service import SqliteAuthorizedShopService
from server.sqlite_shop_store import ShopOffer
from server.sqlite_authorized_quest_inventory_award_service import (
    SqliteAuthorizedQuestInventoryAwardService,
)


ALICE_PASSWORD = "correct horse battery staple"
BOB_PASSWORD = "another correct horse battery staple"


class AuthorizedSyntheticVerticalSliceTests(unittest.TestCase):
    """Exercise shared durable sessions across the existing local domain services."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = os.path.join(self.temp.name, "vertical-slice.sqlite3")
        self.db = sqlite3.connect(
            path, timeout=10, isolation_level=None, check_same_thread=False
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
        clock = lambda: self.now[0]
        self.auth = SqliteAccountAuthService(
            self.db, iterations=100_000, ttl_seconds=300, clock=clock
        )
        self.auth.enroll_password(1, ALICE_PASSWORD)
        self.auth.enroll_password(2, BOB_PASSWORD)
        self.alice = self.auth.authenticate_and_issue_session(
            "alice", ALICE_PASSWORD
        )
        self.bob = self.auth.authenticate_and_issue_session(
            "bob", BOB_PASSWORD
        )
        self.characters = SqliteAuthorizedCharacterService(
            self.db, default_map_id="synthetic_test_map",
            ttl_seconds=300, clock=clock,
        )
        self.maps = SqliteAuthorizedMapService(
            self.db, ttl_seconds=300, clock=clock
        )
        self.inventory = SqliteAuthorizedInventoryService(
            self.db, ttl_seconds=300, clock=clock
        )
        self.quest_awards = SqliteAuthorizedQuestInventoryAwardService(
            self.db, ttl_seconds=300, clock=clock
        )

    def test_authenticated_session_composes_character_map_inventory_and_quest(self):
        bootstrap = self.characters.create_with_initial_state(
            self.alice.token, "Alice", level=2, experience=17
        )
        character_id = bootstrap.character.character_id
        self.assertEqual(bootstrap.character.map_id, "synthetic_test_map")
        self.assertEqual(bootstrap.map_position.revision, 0)

        entered = self.maps.enter(
            self.alice.token, character_id, "enter-1", 0, 7, 10, -4
        )
        self.assertEqual(
            (entered.snapshot.map_id, entered.snapshot.position.x,
             entered.snapshot.position.y, entered.snapshot.revision),
            (7, 10, -4, 1),
        )
        moved = self.maps.move(
            self.alice.token, character_id, "move-1", 1, 7, 12, -3
        )
        self.assertEqual(
            (moved.snapshot.position.x, moved.snapshot.position.y,
             moved.snapshot.revision),
            (12, -3, 2),
        )

        created_inventory = self.inventory.create(
            self.alice.token, character_id, capacity=4, max_stack=10
        )
        self.assertEqual(created_inventory.revision, 0)
        seeded = self.inventory.apply(
            self.alice.token, character_id, "seed-1", 0, [("potion", 2)]
        )
        self.assertEqual(seeded.snapshot.count("potion"), 2)
        self.assertEqual(seeded.snapshot.revision, 1)

        award = self.quest_awards.grant_once(
            self.alice.token, character_id, "quest-7-award", 1, 7, "gem", 1
        )
        self.assertTrue(award.awarded)
        self.assertFalse(award.replayed)
        self.assertEqual(award.snapshot.count("gem"), 1)
        self.assertEqual(award.snapshot.count("potion"), 2)
        self.assertEqual(award.snapshot.revision, 2)

        replay = self.quest_awards.grant_once(
            self.alice.token, character_id, "quest-7-award", 1, 7, "gem", 1
        )
        self.assertFalse(replay.awarded)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.snapshot, award.snapshot)
        self.assertEqual(
            self.inventory.get(self.alice.token, character_id), award.snapshot
        )

    def test_shared_session_enforces_ownership_and_revocation_across_services(self):
        bootstrap = self.characters.create_with_initial_state(
            self.alice.token, "Alice"
        )
        character_id = bootstrap.character.character_id
        self.inventory.create(self.alice.token, character_id)

        with self.assertRaises(SessionError):
            self.maps.get_position(self.bob.token, character_id)
        with self.assertRaises(SessionError):
            self.inventory.get(self.bob.token, character_id)

        self.assertTrue(self.auth.sessions.revoke(self.alice.token))
        with self.assertRaises(SessionError):
            self.maps.get_position(self.alice.token, character_id)
        with self.assertRaises(SessionError):
            self.inventory.get(self.alice.token, character_id)
        with self.assertRaises(SessionError):
            self.quest_awards.grant_once(
                self.alice.token, character_id, "revoked-award", 0, 8, "gem", 1
            )

        renewed = self.auth.authenticate_and_issue_session(
            "alice", ALICE_PASSWORD
        )
        snapshot = self.inventory.get(renewed.token, character_id)
        self.assertEqual(snapshot.items, ())
        self.assertEqual(snapshot.revision, 0)


    def test_shop_and_combat_compose_with_the_same_authorized_session(self):
        bootstrap = self.characters.create_with_initial_state(
            self.alice.token, "Alice", level=2, experience=17
        )
        character_id = bootstrap.character.character_id
        self.inventory.create(
            self.alice.token, character_id, capacity=4, max_stack=10
        )

        players = SqliteAuthorizedPlayerStateService(
            self.db, ttl_seconds=300, clock=lambda: self.now[0]
        )
        funded = players.apply(
            self.alice.token, character_id, "fund-wallet", 0,
            currency_delta=20,
        )
        self.assertEqual(funded.snapshot.currency, 20)
        self.assertEqual(funded.snapshot.revision, 1)

        shop = SqliteAuthorizedShopService(
            self.db,
            {"potion-offer": ShopOffer("potion-offer", "potion", 3)},
            ttl_seconds=300,
            clock=lambda: self.now[0],
        )
        purchase = shop.purchase(
            self.alice.token, character_id, "buy-potions", 1, 0,
            "potion-offer", quantity=2,
        )
        self.assertFalse(purchase.replayed)
        self.assertEqual(purchase.total, 6)
        self.assertEqual(purchase.player.currency, 14)
        self.assertEqual(purchase.player.revision, 2)
        self.assertEqual(purchase.inventory.count("potion"), 2)
        self.assertEqual(purchase.inventory.revision, 1)

        purchase_replay = shop.purchase(
            self.alice.token, character_id, "buy-potions", 1, 0,
            "potion-offer", quantity=2,
        )
        self.assertTrue(purchase_replay.replayed)
        self.assertEqual(purchase_replay.player, purchase.player)
        self.assertEqual(purchase_replay.inventory, purchase.inventory)

        combat = SqliteAuthorizedCombatService(
            self.db, ttl_seconds=300, clock=lambda: self.now[0]
        )
        battle = Battle(
            Fighter(character_id, 20, 7, 2),
            Fighter(9001, 10, 3, 4),
            character_id,
        )
        created = combat.create(
            self.alice.token, character_id, "synthetic-battle", battle
        )
        self.assertEqual(created.revision, 0)

        turn = combat.attack(
            self.alice.token, character_id, "synthetic-battle",
            "player-turn-1", 0, character_id,
        )
        self.assertFalse(turn.replayed)
        self.assertEqual(turn.event.damage, 3)
        self.assertEqual(turn.event.target_hp, 7)
        self.assertEqual(turn.snapshot.revision, 1)

        turn_replay = combat.attack(
            self.alice.token, character_id, "synthetic-battle",
            "player-turn-1", 0, character_id,
        )
        self.assertTrue(turn_replay.replayed)
        self.assertEqual(turn_replay.event, turn.event)
        self.assertEqual(turn_replay.snapshot, turn.snapshot)

        with self.assertRaises(SessionError):
            shop.purchase(
                self.bob.token, character_id, "foreign-purchase", 2, 1,
                "potion-offer", quantity=1,
            )
        with self.assertRaises(SessionError):
            combat.get(self.bob.token, character_id, "synthetic-battle")

        self.assertTrue(self.auth.sessions.revoke(self.alice.token))
        with self.assertRaises(SessionError):
            shop.purchase(
                self.alice.token, character_id, "revoked-purchase", 2, 1,
                "potion-offer", quantity=1,
            )
        with self.assertRaises(SessionError):
            combat.attack(
                self.alice.token, character_id, "synthetic-battle",
                "revoked-turn", 1, 9001,
            )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM shop_purchase_receipts"
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.db.execute(
                "SELECT count(*) FROM combat_mutations"
            ).fetchone()[0],
            1,
        )


if __name__ == "__main__":
    unittest.main()
