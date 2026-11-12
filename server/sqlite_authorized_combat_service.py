"""Durable synthetic combat snapshots; NOT an AOW gameplay or wire contract.

This local domain service persists deterministic transitions from server.combat.
A trusted server-side combat coordinator must choose the actor; this facade is
not exposed as an HTTP route and must not accept client-selected NPC turns.
"""
import json
import re
import sqlite3
from dataclasses import dataclass

from server.combat import Battle, Fighter
from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sessions import SessionError
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_session_store import SqliteSessionStore


_MAX_REVISION = 2**63 - 1
_MAX_RECEIPT_JSON_CHARS = 4096
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError("non-finite JSON constant")


class CombatStoreError(ValueError):
    """Invalid or inconsistent synthetic combat state."""


class CombatNotFound(CombatStoreError):
    """The requested battle does not exist."""


class CombatAlreadyExists(CombatStoreError):
    """The battle identifier is already in use."""


class CombatRevisionConflict(CombatStoreError):
    """The caller's expected battle revision is stale."""


class CombatOperationConflict(CombatStoreError):
    """An idempotency key was reused for another combat action."""


@dataclass(frozen=True)
class CombatSnapshot:
    battle_id: str
    owner_character_id: str
    battle: Battle
    revision: int


@dataclass(frozen=True)
class CombatEvent:
    actor_id: int
    target_id: int
    damage: int
    target_hp: int
    winner_id: int | None
    turn: int


@dataclass(frozen=True)
class CombatMutation:
    snapshot: CombatSnapshot
    event: CombatEvent
    replayed: bool


class SqliteAuthorizedCombatService:
    """Persist deterministic synthetic battle transitions behind ownership.

    The durable session must have been issued after trusted account
    authentication. Exactly one fighter must be the owned character; the
    other fighter is a synthetic opponent. The attack method is a trusted
    domain call: actor selection belongs to the server combat coordinator,
    not the client.
    """

    def __init__(self, connection: sqlite3.Connection, *,
                 ttl_seconds: int = 900, clock=None):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        require_character_schema(connection)
        if (type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= 31_536_000):
            raise ValueError("invalid session ttl")

        self.db = connection
        self.sessions = SqliteSessionStore(
            connection, ttl_seconds=ttl_seconds, clock=clock
        )
        self.authorizer = SqliteCharacterAuthorizer(connection, self.sessions)
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS combat_battles (
                battle_id TEXT PRIMARY KEY
                    CHECK(length(battle_id) BETWEEN 1 AND 128),
                owner_character_id TEXT NOT NULL
                    CHECK(length(owner_character_id) BETWEEN 1 AND 128),
                first_id INTEGER NOT NULL CHECK(first_id BETWEEN 1 AND 1000000),
                first_hp INTEGER NOT NULL CHECK(first_hp BETWEEN 0 AND 1000000),
                first_attack INTEGER NOT NULL CHECK(first_attack BETWEEN 0 AND 1000000),
                first_defense INTEGER NOT NULL CHECK(first_defense BETWEEN 0 AND 1000000),
                second_id INTEGER NOT NULL CHECK(second_id BETWEEN 1 AND 1000000),
                second_hp INTEGER NOT NULL CHECK(second_hp BETWEEN 0 AND 1000000),
                second_attack INTEGER NOT NULL CHECK(second_attack BETWEEN 0 AND 1000000),
                second_defense INTEGER NOT NULL CHECK(second_defense BETWEEN 0 AND 1000000),
                next_actor INTEGER NOT NULL CHECK(next_actor BETWEEN 1 AND 1000000),
                turn INTEGER NOT NULL CHECK(turn BETWEEN 0 AND 1000000),
                revision INTEGER NOT NULL CHECK(revision BETWEEN 0 AND 9223372036854775807),
                winner_id INTEGER,
                CHECK(first_id <> second_id),
                CHECK(next_actor = first_id OR next_actor = second_id)
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS combat_mutations (
                request_id TEXT PRIMARY KEY
                    CHECK(length(request_id) BETWEEN 1 AND 128),
                battle_id TEXT NOT NULL,
                expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
                actor_id INTEGER NOT NULL,
                payload_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY(battle_id) REFERENCES combat_battles(battle_id)
                    ON DELETE CASCADE
            )"""
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS combat_mutations_battle "
            "ON combat_mutations(battle_id, expected_revision)"
        )
        self.db.commit()

    @staticmethod
    def _identifier(value, name):
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise CombatStoreError(f"invalid {name}")
        return value

    @staticmethod
    def _battle_from_row(row):
        return Battle(
            first=Fighter(int(row[2]), int(row[3]), int(row[4]), int(row[5])),
            second=Fighter(int(row[6]), int(row[7]), int(row[8]), int(row[9])),
            next_actor=int(row[10]),
            turn=int(row[11]),
        )

    @classmethod
    def _snapshot_from_row(cls, row):
        return CombatSnapshot(
            battle_id=str(row[0]),
            owner_character_id=str(row[1]),
            battle=cls._battle_from_row(row),
            revision=int(row[12]),
        )

    @staticmethod
    def _battle_json(battle):
        return {
            "first": [
                battle.first.fighter_id, battle.first.hp,
                battle.first.attack, battle.first.defense,
            ],
            "second": [
                battle.second.fighter_id, battle.second.hp,
                battle.second.attack, battle.second.defense,
            ],
            "next_actor": battle.next_actor,
            "turn": battle.turn,
        }

    @classmethod
    def _encode_result(cls, snapshot, event):
        return json.dumps(
            {
                "battle_id": snapshot.battle_id,
                "owner_character_id": snapshot.owner_character_id,
                "battle": cls._battle_json(snapshot.battle),
                "revision": snapshot.revision,
                "event": {
                    "actor_id": event.actor_id,
                    "target_id": event.target_id,
                    "damage": event.damage,
                    "target_hp": event.target_hp,
                    "winner_id": event.winner_id,
                    "turn": event.turn,
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _decode_result(raw):
        """Decode one bounded, unambiguous and internally consistent receipt."""
        if not isinstance(raw, str) or len(raw) > _MAX_RECEIPT_JSON_CHARS:
            raise CombatStoreError("invalid combat receipt")

        try:
            value = json.loads(
                raw,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
            raise CombatStoreError("invalid combat receipt") from exc

        try:
            if type(value) is not dict or set(value) != {
                "battle_id", "owner_character_id", "battle", "revision", "event"
            }:
                raise CombatStoreError("invalid combat receipt fields")

            battle_id = SqliteAuthorizedCombatService._identifier(
                value["battle_id"], "battle identifier"
            )
            owner_character_id = value["owner_character_id"]
            if (not isinstance(owner_character_id, str)
                    or not _IDENTIFIER.fullmatch(owner_character_id)):
                raise CombatStoreError("invalid combat receipt owner")

            revision = value["revision"]
            if type(revision) is not int or not 1 <= revision <= _MAX_REVISION:
                raise CombatStoreError("invalid combat receipt revision")

            battle_data = value["battle"]
            if type(battle_data) is not dict or set(battle_data) != {
                "first", "second", "next_actor", "turn"
            }:
                raise CombatStoreError("invalid combat receipt battle")
            first_data = battle_data["first"]
            second_data = battle_data["second"]
            if (type(first_data) is not list or len(first_data) != 4
                    or type(second_data) is not list or len(second_data) != 4):
                raise CombatStoreError("invalid combat receipt fighters")

            next_actor = battle_data["next_actor"]
            turn = battle_data["turn"]
            if type(next_actor) is not int or type(turn) is not int:
                raise CombatStoreError("invalid combat receipt turn")
            first = Fighter(*first_data)
            second = Fighter(*second_data)
            battle = Battle(first, second, next_actor, turn)
            if revision != battle.turn:
                raise CombatStoreError("combat receipt revision/turn mismatch")

            event_data = value["event"]
            if type(event_data) is not dict or set(event_data) != {
                "actor_id", "target_id", "damage", "target_hp",
                "winner_id", "turn"
            }:
                raise CombatStoreError("invalid combat receipt event")
            actor_id = event_data["actor_id"]
            target_id = event_data["target_id"]
            damage = event_data["damage"]
            target_hp = event_data["target_hp"]
            winner_id = event_data["winner_id"]
            event_turn = event_data["turn"]
            integer_values = (actor_id, target_id, damage, target_hp, event_turn)
            if any(type(item) is not int for item in integer_values):
                raise CombatStoreError("invalid combat receipt event values")
            if (not 1 <= actor_id <= 1_000_000
                    or not 1 <= target_id <= 1_000_000
                    or actor_id == target_id
                    or not 1 <= damage <= 1_000_000
                    or not 0 <= target_hp <= 1_000_000
                    or not 1 <= event_turn <= 1_000_000):
                raise CombatStoreError("combat receipt event outside limits")
            if winner_id is not None and (
                type(winner_id) is not int or not 1 <= winner_id <= 1_000_000
            ):
                raise CombatStoreError("invalid combat receipt winner")

            fighters = {first.fighter_id: first, second.fighter_id: second}
            if actor_id not in fighters or target_id not in fighters:
                raise CombatStoreError("combat receipt references an unknown fighter")
            if fighters[actor_id].hp <= 0:
                raise CombatStoreError("combat receipt actor is defeated")
            if (fighters[target_id].hp != target_hp
                    or target_hp + damage > 1_000_000
                    or event_turn != battle.turn):
                raise CombatStoreError("combat receipt event does not match battle")
            if winner_id is None:
                if target_hp == 0 or battle.next_actor != target_id:
                    raise CombatStoreError("invalid non-terminal combat receipt")
            elif (target_hp != 0 or winner_id != actor_id
                  or battle.next_actor != actor_id):
                raise CombatStoreError("invalid terminal combat receipt")

            snapshot = CombatSnapshot(
                battle_id, owner_character_id, battle, revision
            )
            event = CombatEvent(
                actor_id, target_id, damage, target_hp, winner_id, event_turn
            )
            return snapshot, event
        except CombatStoreError:
            raise
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise CombatStoreError("invalid combat receipt") from exc

    def create(self, token: str, character_id: int, battle_id: str,
               battle: Battle) -> CombatSnapshot:
        """Create a new synthetic battle for an owned participating character."""
        battle_id = self._identifier(battle_id, "battle identifier")
        if not isinstance(battle, Battle):
            raise CombatStoreError("battle snapshot required")
        if battle.turn != 0 or battle.first.hp <= 0 or battle.second.hp <= 0:
            raise CombatStoreError("new battle must start with living fighters")

        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            participant_ids = (battle.first.fighter_id, battle.second.fighter_id)
            if participant_ids.count(character_id) != 1:
                raise SessionError("character does not own this battle")
            try:
                self.db.execute(
                    """INSERT INTO combat_battles
                       (battle_id, owner_character_id,
                        first_id, first_hp, first_attack, first_defense,
                        second_id, second_hp, second_attack, second_defense,
                        next_actor, turn, revision, winner_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)""",
                    (
                        battle_id, owned_id,
                        battle.first.fighter_id, battle.first.hp,
                        battle.first.attack, battle.first.defense,
                        battle.second.fighter_id, battle.second.hp,
                        battle.second.attack, battle.second.defense,
                        battle.next_actor, battle.turn,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CombatAlreadyExists("battle already exists") from exc
            return CombatSnapshot(battle_id, owned_id, battle, 0)

    def get(self, token: str, character_id: int,
            battle_id: str) -> CombatSnapshot:
        """Read a battle only for the character that created it."""
        battle_id = self._identifier(battle_id, "battle identifier")
        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            row = self.db.execute(
                """SELECT battle_id, owner_character_id,
                          first_id, first_hp, first_attack, first_defense,
                          second_id, second_hp, second_attack, second_defense,
                          next_actor, turn, revision, winner_id
                   FROM combat_battles WHERE battle_id=?""",
                (battle_id,),
            ).fetchone()
            if row is None:
                raise CombatNotFound("battle not found")
            if row[1] != owned_id:
                raise SessionError("character does not own this battle")
            return self._snapshot_from_row(row)

    def attack(self, token: str, character_id: int, battle_id: str,
               request_id: str, expected_revision: int,
               actor_id: int) -> CombatMutation:
        """Apply one trusted server-selected actor turn exactly once.

        Authorization is checked before receipt replay. The request receipt,
        updated battle snapshot and event are committed atomically.
        """
        battle_id = self._identifier(battle_id, "battle identifier")
        request_id = self._identifier(request_id, "request identifier")
        if (type(expected_revision) is not int
                or not 0 <= expected_revision < _MAX_REVISION):
            raise CombatStoreError("invalid expected revision")
        if type(actor_id) is not int or not 1 <= actor_id <= 1_000_000:
            raise CombatStoreError("invalid actor identifier")

        with authorized_character_transaction(
            self.db, self.authorizer, token, character_id
        ) as owned_id:
            payload_json = json.dumps(
                [battle_id, owned_id, expected_revision, actor_id],
                separators=(",", ":"),
            )
            row = self.db.execute(
                """SELECT battle_id, owner_character_id,
                          first_id, first_hp, first_attack, first_defense,
                          second_id, second_hp, second_attack, second_defense,
                          next_actor, turn, revision, winner_id
                   FROM combat_battles WHERE battle_id=?""",
                (battle_id,),
            ).fetchone()
            if row is None:
                raise CombatNotFound("battle not found")
            if row[1] != owned_id:
                raise SessionError("character does not own this battle")

            previous = self.db.execute(
                """SELECT battle_id, expected_revision, actor_id,
                          payload_json, result_json
                   FROM combat_mutations WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:4]) != (
                    battle_id, expected_revision, actor_id, payload_json
                ):
                    raise CombatOperationConflict(
                        "request id reused with different combat action"
                    )
                snapshot, event = self._decode_result(previous[4])
                if (snapshot.battle_id != battle_id
                        or snapshot.owner_character_id != owned_id
                        or snapshot.revision != expected_revision + 1
                        or event.actor_id != actor_id):
                    raise CombatStoreError(
                        "combat receipt does not match the original request"
                    )
                return CombatMutation(snapshot, event, True)

            current = self._snapshot_from_row(row)
            if current.revision != expected_revision:
                raise CombatRevisionConflict("stale battle revision")
            if current.revision >= _MAX_REVISION:
                raise CombatStoreError("battle revision overflow")

            updated_battle, event_data = current.battle.attack(actor_id)
            event = CombatEvent(**event_data)
            updated = CombatSnapshot(
                battle_id, owned_id, updated_battle, current.revision + 1
            )
            result_json = self._encode_result(updated, event)
            result = self.db.execute(
                """UPDATE combat_battles
                   SET first_hp=?, second_hp=?, next_actor=?, turn=?,
                       revision=?, winner_id=?
                   WHERE battle_id=? AND owner_character_id=? AND revision=?""",
                (
                    updated_battle.first.hp, updated_battle.second.hp,
                    updated_battle.next_actor, updated_battle.turn,
                    updated.revision, event.winner_id, battle_id, owned_id,
                    expected_revision,
                ),
            )
            if result.rowcount != 1:
                raise CombatRevisionConflict("battle revision changed")
            self.db.execute(
                """INSERT INTO combat_mutations
                   (request_id, battle_id, expected_revision, actor_id,
                    payload_json, result_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    request_id, battle_id, expected_revision, actor_id,
                    payload_json, result_json,
                ),
            )
            return CombatMutation(updated, event, False)
