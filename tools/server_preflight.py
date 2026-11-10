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


REQUIRED_COLUMNS = {
    "accounts": {"id", "username"},
    "characters": {"id", "account_id", "name", "map_id", "x", "y"},
    "wallets": {"character_id", "balance"},
    "shop_catalog": {"item_id", "price", "enabled"},
    "inventory": {"character_id", "item_id", "quantity"},
}


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

        for table, expected in REQUIRED_COLUMNS.items():
            actual = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(" + table + ")"
                )
            }
            if not expected.issubset(actual):
                raise PreflightError("required synthetic table columns are missing")
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
