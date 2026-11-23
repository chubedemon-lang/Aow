"""Read-only integrity audit for the synthetic SQLite domain stores.

This tool does not create schemas, repair records, start a server or infer AOW
protocol behavior. It opens an existing database with SQLite query_only enabled.
"""
import argparse
import json
from pathlib import Path
import sqlite3

from server.sqlite_inventory_store import SqliteInventoryStore
from server.sqlite_map_position_store import SqliteMapPositionStore
from server.sqlite_player_state_store import SqlitePlayerStateStore
from server.sqlite_quest_inventory_award_store import SqliteQuestInventoryAwardStore
from server.sqlite_reward_ledger import SqliteRewardLedger
from server.sqlite_shop_store import SqliteShopStore


class DomainAuditError(ValueError):
    """The database could not be safely audited."""


_STORE_SPECS = (
    (
        "inventory",
        SqliteInventoryStore,
        {"inventory_snapshots", "inventory_items", "inventory_mutations"},
    ),
    (
        "quest_inventory_awards",
        SqliteQuestInventoryAwardStore,
        {"quest_inventory_awards"},
    ),
    (
        "player_state",
        SqlitePlayerStateStore,
        {"player_state_snapshots", "player_state_mutations"},
    ),
    (
        "map_position",
        SqliteMapPositionStore,
        {"map_position_snapshots", "map_position_mutations"},
    ),
    (
        "reward_ledger",
        SqliteRewardLedger,
        {"reward_balances", "reward_receipts"},
    ),
)


def _open_read_only(database):
    raw_path = str(database)
    if raw_path == ":memory:":
        raise DomainAuditError("a persistent SQLite file is required")

    path = Path(database)
    if path.is_symlink():
        raise DomainAuditError("database symlinks are not accepted")

    try:
        if not path.is_file():
            raise DomainAuditError("database file does not exist")
        resolved = path.resolve(strict=True)
        connection = sqlite3.connect(
            resolved.as_uri() + "?mode=ro",
            uri=True,
            timeout=3,
        )
        # Foreign-key enforcement is connection-local and defaults to OFF
        # for a fresh SQLite connection. Enable it before query_only and before
        # any transaction so every store integrity audit sees the same runtime
        # enforcement state required by its write path.
        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise DomainAuditError("SQLite foreign-key enforcement is unavailable")
        connection.execute("PRAGMA query_only = ON")
        return connection
    except DomainAuditError:
        raise
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        raise DomainAuditError("database cannot be opened read-only") from exc


def _audit_existing_store(store_type, connection):
    # Constructors execute CREATE TABLE/INDEX IF NOT EXISTS and commit. Bypass
    # them deliberately: the audit must never initialize or migrate a database.
    store = object.__new__(store_type)
    store.db = connection
    return store.verify_integrity()


def inspect_domain_database(database):
    """Audit only domain stores whose complete schemas already exist.

    A partial store schema is an error. A database with none of these domain
    stores is reported explicitly rather than silently treated as audited.
    """
    connection = _open_read_only(database)
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchall()
        if quick_check != [("ok",)]:
            raise DomainAuditError("SQLite quick_check failed")

        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise DomainAuditError("SQLite foreign-key check failed")

        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }

        # The quest- prefix is reserved by SqliteQuestInventoryAwardStore.
        # If such an inventory mutation exists, its award table must exist too.
        if ("inventory_mutations" in tables
                and "quest_inventory_awards" not in tables):
            reserved_count = connection.execute(
                """SELECT COUNT(*) FROM inventory_mutations
                   WHERE substr(request_id, 1, 6) = 'quest-'"""
            ).fetchone()[0]
            if reserved_count:
                raise DomainAuditError(
                    "quest inventory award schema is missing for reserved inventory mutations"
                )

        # Quest awards are linked to the inventory mutation receipt created in
        # the same transaction. Never report them as audited without that full
        # inventory schema being present.
        if "quest_inventory_awards" in tables and not {
            "inventory_snapshots", "inventory_items", "inventory_mutations"
        }.issubset(tables):
            raise DomainAuditError(
                "quest_inventory_awards requires complete inventory schema"
            )

        shop_reserved_mutations = 0
        for table in ("player_state_mutations", "inventory_mutations"):
            if table in tables:
                shop_reserved_mutations += connection.execute(
                    f"""SELECT COUNT(*) FROM {table}
                        WHERE substr(request_id, 1, 5) = 'shop-'"""
                ).fetchone()[0]

        shop_active = (
            "shop_purchase_receipts" in tables or shop_reserved_mutations > 0
        )
        shop_required_tables = {
            "shop_purchase_receipts",
            "player_state_snapshots",
            "player_state_mutations",
            "inventory_snapshots",
            "inventory_items",
            "inventory_mutations",
        }
        if shop_active and not shop_required_tables.issubset(tables):
            if "shop_purchase_receipts" not in tables:
                raise DomainAuditError(
                    "shop receipt schema is missing for reserved shop mutations"
                )
            raise DomainAuditError("shop schema is incomplete")

        audits = {}
        for name, store_type, required_tables in _STORE_SPECS:
            present = required_tables & tables
            if not present:
                continue
            if present != required_tables:
                raise DomainAuditError(name + " schema is incomplete")
            try:
                audits[name] = _audit_existing_store(store_type, connection)
            except (sqlite3.Error, TypeError, ValueError) as exc:
                raise DomainAuditError(name + " integrity audit failed") from exc

        if shop_active:
            try:
                audits["shop"] = _audit_existing_store(
                    SqliteShopStore, connection
                )
            except (sqlite3.Error, TypeError, ValueError) as exc:
                raise DomainAuditError("shop integrity audit failed") from exc

        return {
            "status": "ok" if audits else "no_domain_stores",
            "sqlite_integrity": "ok",
            "foreign_key_violations": 0,
            "audits": audits,
        }
    except DomainAuditError:
        raise
    except sqlite3.Error as exc:
        raise DomainAuditError("SQLite domain inspection failed") from exc
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, help="existing SQLite database")
    args = parser.parse_args(argv)

    try:
        result = inspect_domain_database(args.db)
    except DomainAuditError as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
