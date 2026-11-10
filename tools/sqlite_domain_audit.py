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


class DomainAuditError(ValueError):
    """The database could not be safely audited."""


_STORE_SPECS = (
    (
        "inventory",
        SqliteInventoryStore,
        {"inventory_snapshots", "inventory_items", "inventory_mutations"},
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
