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
MAX_SCHEMA_SQL_CHARS = 64 * 1024


REQUIRED_CHECKS = {
    "wallets": {
        (("identifier", "balance"), ("operator", ">="), ("number", "0")),
    },
    "shop_catalog": {
        (("identifier", "price"), ("operator", ">"), ("number", "0")),
        (
            ("identifier", "enabled"),
            ("keyword", "in"),
            ("punctuation", "("),
            ("number", "0"),
            ("punctuation", ","),
            ("number", "1"),
            ("punctuation", ")"),
        ),
    },
    "inventory": {
        (("identifier", "quantity"), ("operator", ">="), ("number", "0")),
    },
}


def _quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


def _normalize_sql_fragment(value):
    if value is None:
        return None
    return "".join(str(value).lower().split())


def _tokenize_sql(sql):
    """Tokenize bounded schema SQL, excluding comments and string-literal contents."""
    if type(sql) is not str or len(sql) > MAX_SCHEMA_SQL_CHARS:
        return [("invalid", "schema-sql-limit")]
    tokens = []
    index = 0
    operators = ("->>", "<<", ">>", "->", ">=", "<=", "<>", "!=", "==", "||")

    while index < len(sql):
        character = sql[index]
        if character.isspace():
            index += 1
            continue
        if sql.startswith("--", index):
            newline = sql.find("\n", index + 2)
            index = len(sql) if newline < 0 else newline + 1
            continue
        if sql.startswith("/*", index):
            end = sql.find("*/", index + 2)
            if end < 0:
                tokens.append(("invalid", "unterminated-comment"))
                break
            index = end + 2
            continue
        if character == "'":
            index += 1
            closed = False
            while index < len(sql):
                if sql[index] == "'":
                    if index + 1 < len(sql) and sql[index + 1] == "'":
                        index += 2
                        continue
                    index += 1
                    closed = True
                    break
                index += 1
            if not closed:
                tokens.append(("invalid", "unterminated-string"))
                break
            tokens.append(("string", ""))
            continue
        if character in ('"', "`", "["):
            closing = "]" if character == "[" else character
            index += 1
            value = []
            closed = False
            while index < len(sql):
                if sql[index] == closing:
                    if closing != "]" and index + 1 < len(sql) and sql[index + 1] == closing:
                        value.append(closing)
                        index += 2
                        continue
                    index += 1
                    closed = True
                    break
                value.append(sql[index])
                index += 1
            if not closed:
                tokens.append(("invalid", "unterminated-identifier"))
                break
            tokens.append(("identifier", "".join(value).lower()))
            continue
        if character.isalpha() or character == "_":
            start = index
            index += 1
            while index < len(sql) and (sql[index].isalnum() or sql[index] in "_$"):
                index += 1
            word = sql[start:index].lower()
            kind = "keyword" if word in {"check", "in"} else "identifier"
            tokens.append((kind, word))
            continue
        if character.isdigit():
            start = index
            index += 1
            while index < len(sql) and (sql[index].isalnum() or sql[index] in "._"):
                index += 1
            tokens.append(("number", sql[start:index].lower()))
            continue

        operator = next((item for item in operators if sql.startswith(item, index)), None)
        if operator is not None:
            tokens.append(("operator", operator))
            index += len(operator)
            continue
        if character in "(),":
            tokens.append(("punctuation", character))
            index += 1
            continue
        if character in "=><+-*/%|&~":
            tokens.append(("operator", character))
            index += 1
            continue
        tokens.append(("other", character))
        index += 1

    return tokens


def _extract_check_expressions(sql):
    """Return balanced CHECK expressions, ignoring comments and quoted strings."""
    tokens = _tokenize_sql(sql)
    # A valid CHECK found before malformed trailing SQL is not sufficient:
    # reject the entire schema fragment if tokenization encountered an
    # unterminated comment or quoted token.
    if any(kind == "invalid" for kind, _value in tokens):
        return set()
    expressions = set()
    for index, token in enumerate(tokens[:-1]):
        if token != ("keyword", "check") or tokens[index + 1] != ("punctuation", "("):
            continue
        depth = 1
        expression = []
        cursor = index + 2
        while cursor < len(tokens):
            current = tokens[cursor]
            if current == ("punctuation", "("):
                depth += 1
            elif current == ("punctuation", ")"):
                depth -= 1
                if depth == 0:
                    break
            expression.append(current)
            cursor += 1
        if depth == 0:
            expressions.add(tuple(expression))
    return expressions


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

            # PRAGMA foreign_key_list emits one row per column in a foreign-key
            # constraint. A composite FK that happens to mention a required
            # column must not masquerade as the independent ownership FK that
            # this synthetic schema contract expects.
            foreign_key_groups = {}
            for row in connection.execute(
                "PRAGMA foreign_key_list(" + quoted_table + ")"
            ).fetchall():
                group_id, sequence = int(row[0]), int(row[1])
                foreign_key_groups.setdefault(group_id, []).append((
                    sequence,
                    row[3], row[2], row[4],
                    str(row[5]).upper(), str(row[6]).upper(),
                ))
            foreign_keys = {
                entries[0][1:]
                for entries in foreign_key_groups.values()
                if len(entries) == 1 and entries[0][0] == 0
            }
            if not REQUIRED_FOREIGN_KEYS.get(table, set()).issubset(foreign_keys):
                raise PreflightError("required synthetic foreign-key constraints are missing")

            table_sql_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            check_expressions = _extract_check_expressions(
                table_sql_row[0] if table_sql_row else ""
            )
            if not REQUIRED_CHECKS.get(table, set()).issubset(check_expressions):
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
