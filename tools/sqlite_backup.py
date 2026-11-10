"""Verified, non-overwriting SQLite backups for local synthetic server data.

The utility reads a database through SQLite's read-only URI, uses the SQLite
online-backup API (including committed WAL content), validates the copied
database, and publishes it atomically without replacing an existing path.
It is an operational utility, not an AOW protocol or production-deployment
claim.
"""
from dataclasses import asdict, dataclass
import argparse
import json
import os
from pathlib import Path
import sqlite3
import tempfile


class BackupError(ValueError):
    """The requested SQLite backup could not be safely completed."""


@dataclass(frozen=True)
class BackupReport:
    destination: str
    page_count: int
    tables: tuple[str, ...]
    integrity: str
    foreign_key_violations: int


def _source_path(value):
    if not isinstance(value, (str, os.PathLike)):
        raise BackupError("source must be a persistent SQLite file")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or raw == ":memory:":
        raise BackupError("source must be a persistent SQLite file")
    path = Path(raw)
    if path.is_symlink():
        raise BackupError("source symlinks are not accepted")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BackupError("source file is unavailable") from exc
    if not resolved.is_file():
        raise BackupError("source must be a regular SQLite file")
    return resolved


def _destination_path(value):
    if not isinstance(value, (str, os.PathLike)):
        raise BackupError("destination must be a new file path")
    raw = os.fspath(value)
    if not isinstance(raw, str) or not raw or raw == ":memory:":
        raise BackupError("destination must be a new file path")
    path = Path(raw)
    if path.name in ("", ".", ".."):
        raise BackupError("destination must name a file")
    if path.is_symlink() or path.exists():
        raise BackupError("destination already exists or is a symlink")
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BackupError("destination directory is unavailable") from exc
    if not parent.is_dir():
        raise BackupError("destination parent must be a directory")
    return parent / path.name


def _validate_backup(connection):
    integrity = connection.execute("PRAGMA quick_check").fetchall()
    if integrity != [("ok",)]:
        raise BackupError("backup failed SQLite integrity check")

    foreign_key_errors = connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchall()
    if foreign_key_errors:
        raise BackupError("backup contains foreign-key violations")

    tables = tuple(sorted(
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    ))
    page_count = connection.execute("PRAGMA page_count").fetchone()[0]
    if type(page_count) is not int or page_count < 1:
        raise BackupError("backup has an invalid page count")
    return page_count, tables


def create_backup(source, destination):
    """Create and verify a SQLite snapshot without overwriting any file.

    The source is opened read-only. A temporary database is created in the
    destination directory, populated with Connection.backup(), checked with
    quick_check and foreign_key_check, then published using an atomic hard
    link. The hard link fails if another process creates the destination first.
    Filesystems that do not support hard links fail closed.
    """
    source_path = _source_path(source)
    destination_path = _destination_path(destination)
    if source_path == destination_path:
        raise BackupError("source and destination must be different files")

    temp_path = None
    source_db = None
    backup_db = None
    published = False
    try:
        fd, temp_name = tempfile.mkstemp(
            prefix="." + destination_path.name + ".",
            suffix=".tmp",
            dir=str(destination_path.parent),
        )
        os.close(fd)
        temp_path = Path(temp_name)
        os.chmod(temp_path, 0o600)

        source_uri = source_path.as_uri() + "?mode=ro"
        source_db = sqlite3.connect(
            source_uri, uri=True, timeout=10, isolation_level=None
        )
        backup_db = sqlite3.connect(
            str(temp_path), timeout=10, isolation_level=None
        )
        source_db.backup(backup_db)
        page_count, tables = _validate_backup(backup_db)
        backup_db.close()
        backup_db = None
        source_db.close()
        source_db = None

        with temp_path.open("rb") as stream:
            os.fsync(stream.fileno())

        # os.link is an atomic no-replace publication on the same filesystem.
        os.link(str(temp_path), str(destination_path))
        published = True
        temp_path.unlink()
        temp_path = None

        if os.name == "posix":
            directory_fd = os.open(str(destination_path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        return BackupReport(
            destination=str(destination_path),
            page_count=page_count,
            tables=tables,
            integrity="ok",
            foreign_key_violations=0,
        )
    except BackupError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise BackupError("SQLite backup could not be completed safely") from exc
    finally:
        if backup_db is not None:
            backup_db.close()
        if source_db is not None:
            source_db.close()
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        if published and destination_path.exists() and temp_path is not None:
            # A failed publication cleanup must never leave a partial target.
            try:
                destination_path.unlink()
            except OSError:
                pass


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create a verified, non-overwriting SQLite backup."
    )
    parser.add_argument("source", help="existing SQLite database file")
    parser.add_argument("destination", help="new backup path; must not exist")
    args = parser.parse_args(argv)
    try:
        report = create_backup(args.source, args.destination)
    except BackupError as exc:
        parser.exit(2, "backup failed: " + str(exc) + "\n")
    print(json.dumps(asdict(report), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
