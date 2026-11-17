"""Exact SQLite connection and trusted authorization object boundaries."""

import sqlite3
import unittest

from server.sqlite_authorized_character_service import (
    SqliteAuthorizedCharacterService,
    require_character_lifecycle_schema,
)
from server.sqlite_authorized_combat_service import SqliteAuthorizedCombatService
from server.sqlite_authorized_map_position_service import SqliteAuthorizedMapPositionService
from server.sqlite_authorized_player_bootstrap_service import (
    SqliteAuthorizedPlayerBootstrapService,
)
from server.sqlite_authorized_player_state_service import (
    SqliteAuthorizedPlayerStateService,
)
from server.sqlite_authorized_shop_service import SqliteAuthorizedShopService
from server.sqlite_authorized_transaction import authorized_character_transaction
from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_map_position_store import SqliteMapPositionStore
from server.sqlite_reward_ledger import SqliteRewardLedger
from server.sqlite_shop_store import SqliteShopStore
from server.sqlite_authorized_world_state_service import (
    SqliteAuthorizedWorldStateService,
)
from server.sqlite_character_authorizer import (
    SqliteCharacterAuthorizer,
    require_character_schema,
)
from server.sqlite_session_store import SqliteSessionStore


class _HookedConnection(sqlite3.Connection):
    hook_calls = []

    @property
    def in_transaction(self):
        type(self).hook_calls.append("in_transaction")
        raise AssertionError("overridden in_transaction must not be invoked")

    def execute(self, *args, **kwargs):
        type(self).hook_calls.append("execute")
        raise AssertionError("overridden execute must not be invoked")


class _HostileSessionStore(SqliteSessionStore):
    @property
    def db(self):
        raise AssertionError("session-store subclass accessor must not be invoked")

    def resolve(self, token):
        raise AssertionError("session-store subclass method must not be invoked")

    def resolve_in_transaction(self, token):
        raise AssertionError("session-store subclass method must not be invoked")


class _HostileAuthorizer(SqliteCharacterAuthorizer):
    @property
    def db(self):
        raise AssertionError("authorizer subclass accessor must not be invoked")


class SqliteConnectionBoundaryTests(unittest.TestCase):
    def test_public_schema_and_service_boundaries_reject_connection_subclasses_first(self):
        connection = sqlite3.connect(":memory:", factory=_HookedConnection)
        self.addCleanup(connection.close)

        operations = (
            ("character schema", lambda: require_character_schema(connection)),
            ("character lifecycle schema", lambda: require_character_lifecycle_schema(connection)),
            ("authorizer must support transactional authorization", lambda: SqliteCharacterAuthorizer(connection, None)),
            ("character service", lambda: SqliteAuthorizedCharacterService(connection)),
            ("player state service", lambda: SqliteAuthorizedPlayerStateService(connection)),
            ("map position service", lambda: SqliteAuthorizedMapPositionService(connection)),
            ("combat service", lambda: SqliteAuthorizedCombatService(connection)),
            ("shop service", lambda: SqliteAuthorizedShopService(connection, {})),
            ("world state service", lambda: SqliteAuthorizedWorldStateService(connection)),
            ("player bootstrap service", lambda: SqliteAuthorizedPlayerBootstrapService(connection)),
            ("inventory store", lambda: SqliteInventoryStore(connection)),
            ("map position store", lambda: SqliteMapPositionStore(connection)),
            ("shop store", lambda: SqliteShopStore(connection, {})),
            ("reward ledger", lambda: SqliteRewardLedger(connection)),
        )

        for name, operation in operations:
            with self.subTest(boundary=name):
                _HookedConnection.hook_calls.clear()
                with self.assertRaises(TypeError):
                    operation()
                self.assertEqual(_HookedConnection.hook_calls, [])

    def test_transaction_rejects_connection_subclass_before_authorizer_access(self):
        connection = sqlite3.connect(":memory:", factory=_HookedConnection)
        self.addCleanup(connection.close)

        with self.assertRaises(TypeError):
            with authorized_character_transaction(
                connection, object(), "not-a-session", 1
            ):
                self.fail("transaction body must not run")
        self.assertEqual(_HookedConnection.hook_calls, [])

    def test_character_authorizer_rejects_session_store_subclasses(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        db.execute(
            "CREATE TABLE characters(id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL)"
        )

        hostile = object.__new__(_HostileSessionStore)
        with self.assertRaisesRegex(ValueError, "session store"):
            SqliteCharacterAuthorizer(db, hostile)

    def test_transaction_rejects_authorizer_subclasses_before_accessors(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        hostile = object.__new__(_HostileAuthorizer)

        with self.assertRaisesRegex(TypeError, "authorizer must support transactional authorization"):
            with authorized_character_transaction(db, hostile, "token", 1):
                self.fail("transaction body must not run")

    def test_transaction_rejects_replaced_session_store_subclass_before_accessors(self):
        db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(db.close)
        db.execute(
            "CREATE TABLE characters(id INTEGER PRIMARY KEY, account_id INTEGER NOT NULL)"
        )
        sessions = SqliteSessionStore(db)
        authorizer = SqliteCharacterAuthorizer(db, sessions)
        authorizer.sessions = object.__new__(_HostileSessionStore)

        with self.assertRaisesRegex(TypeError, "durable session store"):
            with authorized_character_transaction(db, authorizer, "token", 1):
                self.fail("transaction body must not run")


if __name__ == "__main__":
    unittest.main()
