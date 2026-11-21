"""Durable synthetic player progression snapshots; not an AOW wire model.

This store persists explicit server-authorized state changes. It deliberately
does not invent AOW leveling, movement, combat, inventory or economy rules.
"""
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass

from server.synthetic_player_state import PlayerSnapshot


_MAX_LEVEL = 1000
_MAX_EXPERIENCE = 2**63 - 1
_MAX_CURRENCY = 2**31 - 1
_MAX_REVISION = 2**63 - 1

_SNAPSHOT_COLUMNS = {
    "character_id": ("TEXT", 0, 1, None),
    "level": ("INTEGER", 1, 0, None),
    "experience": ("INTEGER", 1, 0, None),
    "currency": ("INTEGER", 1, 0, None),
    "revision": ("INTEGER", 1, 0, None),
    "baseline_version": ("INTEGER", 1, 0, "0"),
}
_LEGACY_SNAPSHOT_COLUMNS = {
    name: signature
    for name, signature in _SNAPSHOT_COLUMNS.items()
    if name != "baseline_version"
}
_CREATION_COLUMNS = {
    name: signature
    for name, signature in _SNAPSHOT_COLUMNS.items()
    if name != "baseline_version"
}
_MUTATION_COLUMNS = {
    "request_id": ("TEXT", 0, 1, None),
    "character_id": ("TEXT", 1, 0, None),
    "expected_revision": ("INTEGER", 1, 0, None),
    "requested_level": ("INTEGER", 0, 0, None),
    "experience_delta": ("INTEGER", 1, 0, None),
    "currency_delta": ("INTEGER", 1, 0, None),
    "result_level": ("INTEGER", 1, 0, None),
    "result_experience": ("INTEGER", 1, 0, None),
    "result_currency": ("INTEGER", 1, 0, None),
    "result_revision": ("INTEGER", 1, 0, None),
}


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
    Mutations use BEGIN IMMEDIATE when called standalone. Inside a caller-owned
    transaction they use a private savepoint, never committing or rolling back
    the caller's outer transaction.
    """

    def __init__(self, connection: sqlite3.Connection):
        if type(connection) is not sqlite3.Connection:
            raise TypeError("sqlite connection required")
        if connection.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db = connection
        self.db.execute("PRAGMA busy_timeout = 10000")
        try:
            # Schema creation and the legacy baseline-version migration must
            # succeed as one unit. A malformed pre-existing table must not
            # leave half-created player-state tables behind.
            self.db.execute("BEGIN IMMEDIATE")
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
                        CHECK(revision BETWEEN 0 AND 9223372036854775807),
                    baseline_version INTEGER NOT NULL DEFAULT 0
                        CHECK(baseline_version IN (0, 1))
                )"""
            )
            snapshot_columns = {
                row[1] for row in self.db.execute(
                    "PRAGMA table_info(player_state_snapshots)"
                )
            }
            if "baseline_version" not in snapshot_columns:
                # Migrate only the exact legacy layout; do not ALTER a table
                # that merely happens to share the expected table name.
                self._validate_table_columns(
                    "player_state_snapshots", _LEGACY_SNAPSHOT_COLUMNS
                )
                self.db.execute(
                    "ALTER TABLE player_state_snapshots ADD COLUMN "
                    "baseline_version INTEGER NOT NULL DEFAULT 0 "
                    "CHECK(baseline_version IN (0, 1))"
                )
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS player_state_creations (
                    character_id TEXT PRIMARY KEY
                        CHECK(length(character_id) BETWEEN 1 AND 128),
                    level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 1000),
                    experience INTEGER NOT NULL
                        CHECK(experience BETWEEN 0 AND 9223372036854775807),
                    currency INTEGER NOT NULL
                        CHECK(currency BETWEEN 0 AND 2147483647)
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
            self._validate_schema()
            self.db.commit()
        except BaseException:
            if self.db.in_transaction:
                self.db.rollback()
            raise

    def _validate_table_columns(self, table_name, expected_columns):
        """Require an exact table shape before reading or migrating its rows."""
        if type(table_name) is not str or table_name not in {
            "player_state_snapshots",
            "player_state_creations",
            "player_state_mutations",
        }:
            raise PlayerStoreError("invalid player-state table selector")
        table = self.db.execute(
            "SELECT type FROM sqlite_master WHERE name=?", (table_name,)
        ).fetchone()
        if table != ("table",):
            raise PlayerStoreError("incompatible player-state table")
        rows = self.db.execute(
            "PRAGMA table_info(" + table_name + ")"
        ).fetchall()
        actual_columns = {
            row[1]: (
                str(row[2]).strip().upper(),
                int(row[3]),
                int(row[5]),
                row[4],
            )
            for row in rows
        }
        if (len(rows) != len(expected_columns)
                or actual_columns != expected_columns):
            raise PlayerStoreError("incompatible player-state schema")

    def _validate_schema(self):
        """Validate persisted table layouts and the named mutation index."""
        self._validate_table_columns(
            "player_state_snapshots", _SNAPSHOT_COLUMNS
        )
        self._validate_table_columns(
            "player_state_creations", _CREATION_COLUMNS
        )
        self._validate_table_columns(
            "player_state_mutations", _MUTATION_COLUMNS
        )

        index_object = self.db.execute(
            "SELECT type, tbl_name FROM sqlite_master "
            "WHERE name='player_state_mutations_character'"
        ).fetchone()
        if index_object != ("index", "player_state_mutations"):
            raise PlayerStoreError("incompatible player-state mutation index")
        indexes = [
            row for row in self.db.execute(
                "PRAGMA index_list(player_state_mutations)"
            ).fetchall()
            if row[1] == "player_state_mutations_character"
        ]
        if (
            len(indexes) != 1
            or int(indexes[0][2]) != 0
            or indexes[0][3] != "c"
            or (len(indexes[0]) > 4 and int(indexes[0][4]) != 0)
        ):
            raise PlayerStoreError("incompatible player-state mutation index")
        indexed_columns = tuple(
            row[2] for row in self.db.execute(
                "PRAGMA index_info(player_state_mutations_character)"
            ).fetchall()
        )
        if indexed_columns != ("character_id", "result_revision"):
            raise PlayerStoreError("incompatible player-state mutation index")

    @staticmethod
    def _character_id(value):
        if (type(value) is not str or not value.strip()
                or len(value) > 128):
            raise PlayerStoreError("invalid character identifier")
        return value

    @staticmethod
    def _request_id(value):
        if (type(value) is not str or not value.strip()
                or len(value) > 128):
            raise PlayerStoreError("invalid request identifier")
        return value

    @staticmethod
    def _snapshot(row):
        """Decode one persisted row without coercing SQLite storage classes."""
        character_id, level, experience, currency, revision = (
            row[0], row[1], row[2], row[3], row[4]
        )
        if (
            type(character_id) is not str
            or not character_id.strip()
            or len(character_id) > 128
            or type(level) is not int
            or not 1 <= level <= _MAX_LEVEL
            or type(experience) is not int
            or not 0 <= experience <= _MAX_EXPERIENCE
            or type(currency) is not int
            or not 0 <= currency <= _MAX_CURRENCY
            or type(revision) is not int
            or not 0 <= revision <= _MAX_REVISION
        ):
            raise PlayerStoreError("invalid stored player snapshot")
        return PlayerSnapshot(
            character_id=character_id,
            level=level,
            experience=experience,
            currency=currency,
            revision=revision,
        )

    @contextmanager
    def _write_scope(self, savepoint_name: str):
        """Make one operation atomic without taking caller transaction ownership.

        Standalone operations use BEGIN IMMEDIATE. When the caller already owns
        a transaction, a private savepoint makes this operation atomic while
        leaving the outer transaction open for the caller to commit or roll back.
        Savepoint names are selected only by internal callsites.
        """
        owns_transaction = not self.db.in_transaction
        if owns_transaction:
            self.db.execute("BEGIN IMMEDIATE")
        else:
            if savepoint_name not in (
                "player_state_create", "player_state_apply"
            ):
                raise ValueError("invalid player-state savepoint")
            self.db.execute(f"SAVEPOINT {savepoint_name}")
        try:
            yield
            if owns_transaction:
                self.db.commit()
            else:
                self.db.execute(f"RELEASE SAVEPOINT {savepoint_name}")
        except BaseException:
            if owns_transaction:
                self.db.rollback()
            else:
                self.db.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
                self.db.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            raise

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
        with self._write_scope("player_state_create"):
            try:
                self.db.execute(
                    "INSERT INTO player_state_snapshots "
                    "(character_id, level, experience, currency, revision, baseline_version) "
                    "VALUES (?, ?, ?, ?, 0, 1)",
                    (character_id, level, experience, currency),
                )
            except sqlite3.IntegrityError as exc:
                raise PlayerAlreadyExists("player snapshot already exists") from exc
            self.db.execute(
                "INSERT INTO player_state_creations "
                "(character_id, level, experience, currency) VALUES (?, ?, ?, ?)",
                (character_id, level, experience, currency),
            )
        return snapshot

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

    def verify_integrity(self) -> dict:
        """Audit player state in one consistent, read-only SQLite snapshot.

        The connection must be idle. A deferred read transaction pins one
        database snapshot before any audit query, so concurrent commits cannot
        mix snapshots, creation receipts, and mutation history from different
        points in time. The transaction is always rolled back, including when
        validation fails. This is a consistency audit, not a cryptographic
        integrity boundary.
        """
        if self.db.in_transaction:
            raise ValueError("connection must not have an active transaction")
        self.db.execute("BEGIN")
        try:
            # Force SQLite to establish the read snapshot before the audit.
            self.db.execute(
                "SELECT name FROM sqlite_master LIMIT 1"
            ).fetchone()
            return self._verify_integrity_snapshot()
        finally:
            if self.db.in_transaction:
                self.db.rollback()

    def _verify_integrity_snapshot(self) -> dict:
        """Run the audit while verify_integrity owns the read snapshot."""
        if self.db.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise PlayerStoreError("SQLite quick_check failed")
        if self.db.execute("PRAGMA foreign_key_check").fetchall():
            raise PlayerStoreError("player-state foreign key check failed")

        snapshot_columns = {
            row[1] for row in self.db.execute(
                "PRAGMA table_info(player_state_snapshots)"
            )
        }
        has_baseline_version = "baseline_version" in snapshot_columns
        baseline_column = ", baseline_version" if has_baseline_version else ""
        rows = self.db.execute(
            "SELECT character_id, level, experience, currency, revision"
            + baseline_column
            + " FROM player_state_snapshots ORDER BY character_id"
        ).fetchall()

        snapshots = {}
        baseline_versions = {}
        for row in rows:
            snapshot = self._snapshot(row)
            character_id = snapshot.character_id
            baseline_version = row[5] if has_baseline_version else 0
            if character_id in snapshots:
                raise PlayerStoreError("duplicate player snapshot")
            if (type(baseline_version) is not int
                    or baseline_version not in (0, 1)):
                raise PlayerStoreError("invalid stored player snapshot")
            snapshots[character_id] = snapshot
            baseline_versions[character_id] = baseline_version

        tables = {
            row[0] for row in self.db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        baselines = {}
        if "player_state_creations" in tables:
            creation_rows = self.db.execute(
                """SELECT character_id, level, experience, currency
                   FROM player_state_creations ORDER BY character_id"""
            ).fetchall()
        else:
            creation_rows = []

        for character_id, level, experience, currency in creation_rows:
            character_id = self._character_id(character_id)
            if character_id in baselines:
                raise PlayerStoreError("duplicate player creation receipt")
            if character_id not in snapshots:
                raise PlayerStoreError("creation receipt has no player snapshot")
            if baseline_versions[character_id] != 1:
                raise PlayerStoreError("creation receipt baseline marker mismatch")
            if (type(level) is not int or not 1 <= level <= _MAX_LEVEL
                    or type(experience) is not int
                    or not 0 <= experience <= _MAX_EXPERIENCE
                    or type(currency) is not int
                    or not 0 <= currency <= _MAX_CURRENCY):
                raise PlayerStoreError("invalid player creation receipt")
            baselines[character_id] = PlayerSnapshot(
                character_id, level, experience, currency, 0
            )

        for character_id, baseline_version in baseline_versions.items():
            if baseline_version == 1 and character_id not in baselines:
                raise PlayerStoreError("player creation receipt is missing")
            if baseline_version == 0 and character_id in baselines:
                raise PlayerStoreError("creation receipt baseline marker mismatch")

        replayed = dict(baselines)
        mutation_rows = self.db.execute(
            """SELECT request_id, character_id, expected_revision,
                      requested_level, experience_delta, currency_delta,
                      result_level, result_experience, result_currency,
                      result_revision
               FROM player_state_mutations
               ORDER BY character_id, result_revision, request_id"""
        ).fetchall()
        mutation_count = 0

        for (request_id, character_id, expected_revision, requested_level,
             experience_delta, currency_delta, result_level, result_experience,
             result_currency, result_revision) in mutation_rows:
            self._request_id(request_id)
            character_id = self._character_id(character_id)
            if character_id not in snapshots:
                raise PlayerStoreError("mutation has no player snapshot")
            if (type(expected_revision) is not int
                    or not 0 <= expected_revision < _MAX_REVISION
                    or type(result_revision) is not int
                    or result_revision != expected_revision + 1):
                raise PlayerStoreError("invalid player mutation revision")
            if requested_level is not None and (
                type(requested_level) is not int
                or not 1 <= requested_level <= _MAX_LEVEL
            ):
                raise PlayerStoreError("invalid requested player level")
            if (type(experience_delta) is not int
                    or not -_MAX_EXPERIENCE <= experience_delta <= _MAX_EXPERIENCE
                    or type(currency_delta) is not int
                    or not -_MAX_CURRENCY <= currency_delta <= _MAX_CURRENCY):
                raise PlayerStoreError("invalid player mutation delta")
            if (type(result_level) is not int
                    or not 1 <= result_level <= _MAX_LEVEL
                    or type(result_experience) is not int
                    or not 0 <= result_experience <= _MAX_EXPERIENCE
                    or type(result_currency) is not int
                    or not 0 <= result_currency <= _MAX_CURRENCY):
                raise PlayerStoreError("invalid player mutation result")

            current = replayed.get(character_id)
            if current is None:
                # Legacy snapshot: its original level was never stored in a
                # creation receipt, so only deltas and later history are provable.
                if expected_revision != 0:
                    raise PlayerStoreError("player mutation history has a gap")
                baseline_experience = result_experience - experience_delta
                baseline_currency = result_currency - currency_delta
                if (not 0 <= baseline_experience <= _MAX_EXPERIENCE
                        or not 0 <= baseline_currency <= _MAX_CURRENCY):
                    raise PlayerStoreError("invalid first player mutation baseline")
                if (requested_level is not None
                        and result_level != requested_level):
                    raise PlayerStoreError("first player mutation level mismatch")
                current = PlayerSnapshot(
                    character_id, result_level, result_experience,
                    result_currency, result_revision,
                )
            else:
                if current.revision != expected_revision:
                    raise PlayerStoreError("player mutation history has a gap")
                expected_level = (
                    current.level if requested_level is None else requested_level
                )
                expected_experience = current.experience + experience_delta
                expected_currency = current.currency + currency_delta
                if (not 0 <= expected_experience <= _MAX_EXPERIENCE
                        or not 0 <= expected_currency <= _MAX_CURRENCY):
                    raise PlayerStoreError("player mutation history overflows")
                if (result_level, result_experience, result_currency) != (
                    expected_level, expected_experience, expected_currency
                ):
                    raise PlayerStoreError("player mutation receipt does not match history")
                current = PlayerSnapshot(
                    character_id, result_level, result_experience,
                    result_currency, result_revision,
                )
            replayed[character_id] = current
            mutation_count += 1

        for character_id, snapshot in snapshots.items():
            historical = replayed.get(character_id)
            if historical is None:
                if snapshot.revision != 0:
                    raise PlayerStoreError(
                        "player snapshot revision has no mutation history"
                    )
            elif historical.revision != snapshot.revision:
                if snapshot.revision > historical.revision:
                    raise PlayerStoreError(
                        "player snapshot revision has no mutation history"
                    )
                raise PlayerStoreError(
                    "current player snapshot does not match mutation history"
                )
            elif historical != snapshot:
                raise PlayerStoreError(
                    "current player snapshot does not match mutation history"
                )

        return {
            "snapshots": len(snapshots),
            "mutations": mutation_count,
            "anchored_snapshots": len(baselines),
            "legacy_unanchored_snapshots": len(snapshots) - len(baselines),
        }

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
        with self._write_scope("player_state_apply"):
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
            return PlayerMutation(updated, False)
