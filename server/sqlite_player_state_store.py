"""Durable synthetic player progression snapshots; not an AOW wire model.

This store persists explicit server-authorized state changes. It deliberately
does not invent AOW leveling, movement, combat, inventory or economy rules.
"""
import sqlite3
from dataclasses import dataclass

from server.synthetic_player_state import PlayerSnapshot


_MAX_LEVEL = 1000
_MAX_EXPERIENCE = 2**63 - 1
_MAX_CURRENCY = 2**31 - 1
_MAX_REVISION = 2**63 - 1


class PlayerStoreError(ValueError):
    """Invalid or inconsistent durable player state."""


class PlayerNotFound(PlayerStoreError):
    """No durable snapshot exists for the requested character."""


class PlayerAlreadyExists(PlayerStoreError):
    """A snapshot already exists for the requested character."""


class PlayerRevisionConflict(PlayerStoreError):
    """The caller's expected revision is stale."""


class PlayerOperationConflict(PlayerStoreError):
    """An idempotency key was reused with a different mutation."""


@dataclass(frozen=True)
class PlayerMutation:
    snapshot: PlayerSnapshot
    replayed: bool


class SqlitePlayerStateStore:
    """SQLite-backed player snapshots with optimistic revisions and idempotency.

    Every mutation and its receipt commit in one BEGIN IMMEDIATE transaction.
    Mutations start their own transaction when called standalone, or join an
    existing caller-owned transaction without committing or rolling it back.
    """

    def __init__(self, connection: sqlite3.Connection):
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.db.execute("PRAGMA busy_timeout = 10000")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS player_state_snapshots (
                character_id TEXT PRIMARY KEY
                    CHECK(length(character_id) BETWEEN 1 AND 128),
                level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 1000),
                experience INTEGER NOT NULL
                    CHECK(experience BETWEEN 0 AND 9223372036854775807),
                currency INTEGER NOT NULL
                    CHECK(currency BETWEEN 0 AND 2147483647),
                revision INTEGER NOT NULL
                    CHECK(revision BETWEEN 0 AND 9223372036854775807)
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS player_state_mutations (
                request_id TEXT PRIMARY KEY
                    CHECK(length(request_id) BETWEEN 1 AND 128),
                character_id TEXT NOT NULL,
                expected_revision INTEGER NOT NULL CHECK(expected_revision >= 0),
                requested_level INTEGER,
                experience_delta INTEGER NOT NULL,
                currency_delta INTEGER NOT NULL,
                result_level INTEGER NOT NULL,
                result_experience INTEGER NOT NULL,
                result_currency INTEGER NOT NULL,
                result_revision INTEGER NOT NULL
            )"""
        )
        self.db.execute(
            "CREATE INDEX IF NOT EXISTS player_state_mutations_character "
            "ON player_state_mutations(character_id, result_revision)"
        )
        self.db.commit()

    @staticmethod
    def _character_id(value):
        if (not isinstance(value, str) or not value.strip()
                or len(value) > 128):
            raise PlayerStoreError("invalid character identifier")
        return value

    @staticmethod
    def _request_id(value):
        if (not isinstance(value, str) or not value.strip()
                or len(value) > 128):
            raise PlayerStoreError("invalid request identifier")
        return value

    @staticmethod
    def _snapshot(row):
        return PlayerSnapshot(
            character_id=row[0],
            level=int(row[1]),
            experience=int(row[2]),
            currency=int(row[3]),
            revision=int(row[4]),
        )

    def create(self, character_id: str, *, level: int = 1,
               experience: int = 0, currency: int = 0) -> PlayerSnapshot:
        """Create the initial snapshot; duplicate character ids are rejected."""
        character_id = self._character_id(character_id)
        if type(level) is not int or not 1 <= level <= _MAX_LEVEL:
            raise PlayerStoreError("invalid level")
        if (type(experience) is not int
                or not 0 <= experience <= _MAX_EXPERIENCE):
            raise PlayerStoreError("invalid experience")
        if (type(currency) is not int
                or not 0 <= currency <= _MAX_CURRENCY):
            raise PlayerStoreError("invalid currency")

        snapshot = PlayerSnapshot(character_id, level, experience, currency, 0)
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            try:
                self.db.execute(
                    "INSERT INTO player_state_snapshots "
                    "(character_id, level, experience, currency, revision) "
                    "VALUES (?, ?, ?, ?, 0)",
                    (character_id, level, experience, currency),
                )
            except sqlite3.IntegrityError as exc:
                raise PlayerAlreadyExists("player snapshot already exists") from exc
            if owns_transaction:
                self.db.commit()
            return snapshot
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            raise

    def get(self, character_id: str) -> PlayerSnapshot:
        """Read a snapshot without taking ownership of the caller's transaction."""
        character_id = self._character_id(character_id)
        row = self.db.execute(
            "SELECT character_id, level, experience, currency, revision "
            "FROM player_state_snapshots WHERE character_id=?",
            (character_id,),
        ).fetchone()
        if row is None:
            raise PlayerNotFound("player snapshot not found")
        return self._snapshot(row)

    def apply(self, character_id: str, request_id: str, expected_revision: int,
              *, level=None, experience_delta: int = 0,
              currency_delta: int = 0) -> PlayerMutation:
        """Apply an explicit state change once, guarded by an expected revision.

        A replay with the same request id and exact request payload returns the
        original result snapshot, even if the player has since advanced further.
        Reusing the request id for another payload is rejected.
        """
        character_id = self._character_id(character_id)
        request_id = self._request_id(request_id)
        if (type(expected_revision) is not int
                or not 0 <= expected_revision < _MAX_REVISION):
            raise PlayerStoreError("invalid expected revision")
        if level is not None and (
            type(level) is not int or not 1 <= level <= _MAX_LEVEL
        ):
            raise PlayerStoreError("invalid level")
        if (type(experience_delta) is not int
                or not -_MAX_EXPERIENCE <= experience_delta <= _MAX_EXPERIENCE):
            raise PlayerStoreError("invalid experience delta")
        if (type(currency_delta) is not int
                or not -_MAX_CURRENCY <= currency_delta <= _MAX_CURRENCY):
            raise PlayerStoreError("invalid currency delta")
        if level is None and experience_delta == 0 and currency_delta == 0:
            raise PlayerStoreError("empty player mutation")

        request = (
            character_id, expected_revision, level,
            experience_delta, currency_delta,
        )
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        try:
            previous = self.db.execute(
                """SELECT character_id, expected_revision, requested_level,
                          experience_delta, currency_delta, result_level,
                          result_experience, result_currency, result_revision
                   FROM player_state_mutations WHERE request_id=?""",
                (request_id,),
            ).fetchone()
            if previous is not None:
                if tuple(previous[:5]) != request:
                    raise PlayerOperationConflict(
                        "request id reused with different player mutation"
                    )
                replay = PlayerSnapshot(
                    character_id, int(previous[5]), int(previous[6]),
                    int(previous[7]), int(previous[8]),
                )
                if owns_transaction:
                    self.db.commit()
                return PlayerMutation(replay, True)

            row = self.db.execute(
                "SELECT character_id, level, experience, currency, revision "
                "FROM player_state_snapshots WHERE character_id=?",
                (character_id,),
            ).fetchone()
            if row is None:
                raise PlayerNotFound("player snapshot not found")
            current = self._snapshot(row)
            if current.revision != expected_revision:
                raise PlayerRevisionConflict("stale player revision")

            new_level = current.level if level is None else level
            new_experience = current.experience + experience_delta
            new_currency = current.currency + currency_delta
            if not 0 <= new_experience <= _MAX_EXPERIENCE:
                raise PlayerStoreError("experience underflow or overflow")
            if not 0 <= new_currency <= _MAX_CURRENCY:
                raise PlayerStoreError("currency underflow or overflow")
            updated = PlayerSnapshot(
                character_id, new_level, new_experience, new_currency,
                current.revision + 1,
            )
            result = self.db.execute(
                """UPDATE player_state_snapshots
                   SET level=?, experience=?, currency=?, revision=?
                   WHERE character_id=? AND revision=?""",
                (updated.level, updated.experience, updated.currency,
                 updated.revision, character_id, expected_revision),
            )
            if result.rowcount != 1:
                raise PlayerRevisionConflict("player revision changed")

            self.db.execute(
                """INSERT INTO player_state_mutations
                   (request_id, character_id, expected_revision, requested_level,
                    experience_delta, currency_delta, result_level,
                    result_experience, result_currency, result_revision)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (request_id, *request, updated.level, updated.experience,
                 updated.currency, updated.revision),
            )
            if owns_transaction:
                self.db.commit()
            return PlayerMutation(updated, False)
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            raise
