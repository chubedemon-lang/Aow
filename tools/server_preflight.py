"""Read-only preflight for the localhost-only synthetic AOW prototype.

This is an operational sanity check, not a production deployment validator and
not an AOW protocol compatibility test.
"""
import argparse
import json
from pathlib import Path
import sqlite3

from server.runtime_safety import RuntimeSafetyError, validate_loopback_bind


class PreflightError(ValueError):
    """The local synthetic server failed a pre-start safety check."""


REQUIRED_COLUMN_DEFINITIONS = {
    "accounts": {
        "id": ("INTEGER", 0, 1, None),
        "username": ("TEXT", 1, 0, None),
    },
    "characters": {
        "id": ("INTEGER", 0, 1, None),
        "account_id": ("INTEGER", 1, 0, None),
        "name": ("TEXT", 1, 0, None),
        "map_id": ("TEXT", 1, 0, "'test_map'"),
        "x": ("INTEGER", 1, 0, "0"),
        "y": ("INTEGER", 1, 0, "0"),
    },
    "wallets": {
        "character_id": ("INTEGER", 0, 1, None),
        "balance": ("INTEGER", 1, 0, "0"),
    },
    "shop_catalog": {
        "item_id": ("TEXT", 0, 1, None),
        "price": ("INTEGER", 1, 0, None),
        "enabled": ("INTEGER", 1, 0, "1"),
    },
    "inventory": {
        "character_id": ("INTEGER", 1, 1, None),
        "item_id": ("TEXT", 1, 2, None),
        "quantity": ("INTEGER", 1, 0, None),
    },
}
REQUIRED_COLUMNS = {
    table: set(columns) for table, columns in REQUIRED_COLUMN_DEFINITIONS.items()
}
REQUIRED_UNIQUE_KEYS = {
    "accounts": {("username",)},
    "characters": {("account_id",)},
}
REQUIRED_FOREIGN_KEYS = {
    "characters": {("account_id", "accounts", "id", "NO ACTION", "NO ACTION")},
    "wallets": {("character_id", "characters", "id", "NO ACTION", "NO ACTION")},
    "inventory": {("character_id", "characters", "id", "NO ACTION", "NO ACTION")},
}
REQUIRED_CHECKS = {
    "wallets": {"check(balance>=0)"},
    "shop_catalog": {"check(price>0)", "check(enabledin(0,1))"},
    "inventory": {"check(quantity>=0)"},
}


def _quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


def _normalize_sql_fragment(value):
    if value is None:
        return None
    return "".join(str(value).lower().split())



def inspect_synthetic_database(database):
    """Inspect the expected mock schema without creating or modifying the DB."""
    raw_path = str(database)
    if raw_path == ":memory:":
        raise PreflightError("a persistent SQLite file is required")
    path = Path(database)
    if path.is_symlink():
        raise PreflightError("database symlinks are not accepted")
    try:
        if not path.is_file():
            raise PreflightError("database file does not exist")
        resolved = path.resolve(strict=True)
        uri = resolved.as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=3)
    except PreflightError:
        raise
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        raise PreflightError("database cannot be opened read-only") from exc

    try:
        integrity = [row[0] for row in connection.execute("PRAGMA quick_check")]
        if integrity != ["ok"]:
            raise PreflightError("SQLite integrity check failed")

        violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise PreflightError("SQLite foreign-key check failed")

        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        missing_tables = set(REQUIRED_COLUMNS) - tables
        if missing_tables:
            raise PreflightError("required synthetic tables are missing")

        for table, expected in REQUIRED_COLUMN_DEFINITIONS.items():
            quoted_table = _quote_identifier(table)
            rows = connection.execute(
                "PRAGMA table_info(" + quoted_table + ")"
            ).fetchall()
            actual = {
                row[1]: (
                    str(row[2]).strip().upper(),
                    int(row[3]),
                    int(row[5]),
                    _normalize_sql_fragment(row[4]),
                )
                for row in rows
            }
            if not set(expected).issubset(actual):
                raise PreflightError("required synthetic table columns are missing")
            if any(actual[name] != definition for name, definition in expected.items()):
                raise PreflightError("required synthetic column definitions are invalid")

            primary_key = tuple(
                name for name, definition in sorted(
                    expected.items(), key=lambda item: item[1][2]
                ) if definition[2] > 0
            )
            actual_primary_key = tuple(
                row[1] for row in sorted(rows, key=lambda row: row[5]) if row[5] > 0
            )
            if actual_primary_key != primary_key:
                raise PreflightError("required synthetic primary-key layout is invalid")

            unique_keys = set()
            for index in connection.execute(
                "PRAGMA index_list(" + quoted_table + ")"
            ).fetchall():
                if int(index[2]) != 1 or (len(index) > 4 and int(index[4]) != 0):
                    continue
                index_name = _quote_identifier(index[1])
                index_columns = tuple(
                    row[2] for row in connection.execute(
                        "PRAGMA index_info(" + index_name + ")"
                    ).fetchall()
                )
                if index_columns and all(column is not None for column in index_columns):
                    unique_keys.add(index_columns)
            if not REQUIRED_UNIQUE_KEYS.get(table, set()).issubset(unique_keys):
                raise PreflightError("required synthetic unique constraints are missing")

            foreign_keys = {
                (
                    row[3], row[2], row[4],
                    str(row[5]).upper(), str(row[6]).upper(),
                )
                for row in connection.execute(
                    "PRAGMA foreign_key_list(" + quoted_table + ")"
                ).fetchall()
            }
            if not REQUIRED_FOREIGN_KEYS.get(table, set()).issubset(foreign_keys):
                raise PreflightError("required synthetic foreign-key constraints are missing")

            table_sql_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            normalized_table_sql = _normalize_sql_fragment(
                table_sql_row[0] if table_sql_row else None
            ) or ""
            if any(
                check not in normalized_table_sql
                for check in REQUIRED_CHECKS.get(table, set())
            ):
                raise PreflightError("required synthetic CHECK constraints are missing")
    except PreflightError:
        raise
    except sqlite3.Error as exc:
        raise PreflightError("SQLite schema inspection failed") from exc
    finally:
        connection.close()

    return {
        "sqlite_integrity": "ok",
        "foreign_key_violations": 0,
        "required_tables": sorted(REQUIRED_COLUMNS),
        "schema_valid": True,
        "schema_contract": "synthetic-v1",
    }


def run_preflight(host, port, database):
    """Validate local-only bind settings and an existing synthetic DB."""
    normalized_host, normalized_port = validate_loopback_bind(host, port)
    database_result = inspect_synthetic_database(database)
    return {
        "status": "ready_for_local_synthetic_testing",
        "bind_host": normalized_host,
        "port": normalized_port,
        **database_result,
        "apk_compatible": False,
        "production_ready": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db", default="aow_mock.sqlite3")
    args = parser.parse_args(argv)
    try:
        result = run_preflight(args.host, args.port, args.db)
    except (PreflightError, RuntimeSafetyError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
