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
        if type(connection) is not sqlite3.Connection:
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
        # Reject str subclasses before regex, hashing, or SQLite binding can
        # interact with caller-defined behavior. Persisted identifiers and
        # public request identifiers use one canonical built-in str type.
        if type(value) is not str or not _IDENTIFIER.fullmatch(value):
            raise CombatStoreError(f"invalid {name}")
        return value

    @staticmethod
    def _stored_int(value, name, *, minimum, maximum):
        if type(value) is not int or not minimum <= value <= maximum:
            raise CombatStoreError(f"invalid persisted combat {name}")
        return value

    @classmethod
    def _battle_from_row(cls, row):
        if len(row) != 14:
            raise CombatStoreError("invalid persisted combat row")
        first = Fighter(
            cls._stored_int(row[2], "first fighter id", minimum=1, maximum=1_000_000),
            cls._stored_int(row[3], "first fighter hp", minimum=0, maximum=1_000_000),
            cls._stored_int(row[4], "first fighter attack", minimum=0, maximum=1_000_000),
            cls._stored_int(row[5], "first fighter defense", minimum=0, maximum=1_000_000),
        )
        second = Fighter(
            cls._stored_int(row[6], "second fighter id", minimum=1, maximum=1_000_000),
            cls._stored_int(row[7], "second fighter hp", minimum=0, maximum=1_000_000),
            cls._stored_int(row[8], "second fighter attack", minimum=0, maximum=1_000_000),
            cls._stored_int(row[9], "second fighter defense", minimum=0, maximum=1_000_000),
        )
        next_actor = cls._stored_int(
            row[10], "next actor", minimum=1, maximum=1_000_000
        )
        turn = cls._stored_int(row[11], "turn", minimum=0, maximum=1_000_000)
        return Battle(first, second, next_actor, turn)

    @classmethod
    def _snapshot_from_row(cls, row):
        try:
            if len(row) != 14:
                raise CombatStoreError("invalid persisted combat row")
            battle_id = cls._identifier(row[0], "battle identifier")
            owner_character_id = cls._identifier(
                row[1], "owner character identifier"
            )
            battle = cls._battle_from_row(row)
            revision = cls._stored_int(
                row[12], "revision", minimum=0, maximum=_MAX_REVISION
            )
            winner_id = row[13]

            if revision != battle.turn:
                raise CombatStoreError("persisted combat revision/turn mismatch")

            if winner_id is None:
                if battle.first.hp == 0 or battle.second.hp == 0:
                    raise CombatStoreError(
                        "persisted non-terminal combat has a defeated fighter"
                    )
            else:
                winner_id = cls._stored_int(
                    winner_id, "winner id", minimum=1, maximum=1_000_000
                )
                fighters = {
                    battle.first.fighter_id: battle.first,
                    battle.second.fighter_id: battle.second,
                }
                loser_ids = set(fighters) - {winner_id}
                if (
                    winner_id not in fighters
                    or battle.turn < 1
                    or fighters[winner_id].hp <= 0
                    or len(loser_ids) != 1
                    or fighters[next(iter(loser_ids))].hp != 0
                    or battle.next_actor != winner_id
                ):
                    raise CombatStoreError(
                        "persisted combat winner does not match battle state"
                    )

            return CombatSnapshot(
                battle_id, owner_character_id, battle, revision
            )
        except CombatStoreError:
            raise
        except (IndexError, TypeError, ValueError, OverflowError) as exc:
            raise CombatStoreError("invalid persisted combat snapshot") from exc

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
        if type(raw) is not str or len(raw) > _MAX_RECEIPT_JSON_CHARS:
            # Exact type check must precede len(): a str subclass can override
            # __len__ and execute arbitrary caller code during receipt parsing.
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
            if (type(owner_character_id) is not str
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

    def verify_integrity(self) -> dict:
        """Audit battle snapshots and their durable turn receipts read-only.

        Every committed turn must have exactly one receipt for its expected
        revision, revisions must form a contiguous chain from zero, and the
        latest receipt must equal the current battle snapshot. The initial
        battle state is not separately receipted by this schema, so the audit
        cannot independently prove the creation baseline.
        """
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN")
        try:
            return self._verify_integrity_snapshot()
        finally:
            if self.db.in_transaction:
                self.db.rollback()

    def _verify_integrity_snapshot(self) -> dict:
        """Run the audit inside verify_integrity's pinned read snapshot."""
        if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise CombatStoreError("SQLite quick_check failed")
        if self.db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise CombatStoreError("combat foreign key check failed")

        battles = {}
        battle_rows = self.db.execute(
            """SELECT battle_id, owner_character_id,
                      first_id, first_hp, first_attack, first_defense,
                      second_id, second_hp, second_attack, second_defense,
                      next_actor, turn, revision, winner_id
               FROM combat_battles ORDER BY battle_id"""
        )
        for row in battle_rows:
            snapshot = self._snapshot_from_row(row)
            if snapshot.battle_id in battles:
                raise CombatStoreError("duplicate persisted battle")
            battles[snapshot.battle_id] = snapshot

        next_revision = {battle_id: 0 for battle_id in battles}
        latest_receipt = {}
        mutation_count = 0
        mutation_rows = self.db.execute(
            """SELECT request_id, battle_id, expected_revision, actor_id,
                      payload_json, result_json
               FROM combat_mutations
               ORDER BY battle_id, expected_revision, request_id"""
        )
        for (request_id, battle_id, expected_revision, actor_id,
             payload_json, result_json) in mutation_rows:
            request_id = self._identifier(request_id, "request identifier")
            battle_id = self._identifier(battle_id, "battle identifier")
            if battle_id not in battles:
                raise CombatStoreError("combat mutation has no battle")
            if (type(expected_revision) is not int
                    or not 0 <= expected_revision < _MAX_REVISION):
                raise CombatStoreError("invalid stored combat mutation revision")
            if type(actor_id) is not int or not 1 <= actor_id <= 1_000_000:
                raise CombatStoreError("invalid stored combat mutation actor")

            owner_character_id = battles[battle_id].owner_character_id
            expected_payload = json.dumps(
                [battle_id, owner_character_id, expected_revision, actor_id],
                separators=(",", ":"),
            )
            if (type(payload_json) is not str or len(payload_json) > 512
                    or payload_json != expected_payload):
                raise CombatStoreError("combat mutation payload is not canonical")

            receipt_snapshot, event = self._decode_result(result_json)
            if self._encode_result(receipt_snapshot, event) != result_json:
                raise CombatStoreError("combat mutation result is not canonical")
            if (receipt_snapshot.battle_id != battle_id
                    or receipt_snapshot.owner_character_id != owner_character_id
                    or receipt_snapshot.revision != expected_revision + 1
                    or event.actor_id != actor_id):
                raise CombatStoreError("combat mutation receipt does not match its row")

            expected_next = next_revision[battle_id]
            if expected_revision != expected_next:
                raise CombatStoreError(
                    "combat mutation revision history has a gap or duplicate"
                )
            next_revision[battle_id] = expected_next + 1
            latest_receipt[battle_id] = receipt_snapshot
            mutation_count += 1

        for battle_id, current in battles.items():
            if next_revision[battle_id] != current.revision:
                raise CombatStoreError(
                    "combat mutation history does not reach current revision"
                )
            if current.revision > 0 and latest_receipt.get(battle_id) != current:
                raise CombatStoreError(
                    "current combat snapshot does not match latest receipt"
                )

        return {
            "battles": len(battles),
            "mutations": mutation_count,
            "unanchored_battles": len(battles),
        }

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
