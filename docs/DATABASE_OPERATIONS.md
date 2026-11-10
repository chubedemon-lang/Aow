# Local SQLite backup operations

`tools/sqlite_backup.py` creates a verified snapshot of one persistent SQLite
database without modifying the source or overwriting an existing destination.

## Usage

```sh
python -m tools.sqlite_backup ./data/aow.sqlite3 ./backups/aow-2026-11-11.sqlite3
```

The command:

1. rejects a missing/non-regular source, source symlinks, an existing destination,
   destination symlinks, and an unavailable destination directory;
2. opens the source with SQLite's read-only URI mode;
3. uses `Connection.backup()` so committed data in a WAL is included in the
   snapshot;
4. checks `PRAGMA quick_check` and `PRAGMA foreign_key_check` on the copy;
5. publishes the completed file with an atomic same-filesystem hard link that
   cannot replace a destination created by another process.

The destination directory must already exist. The destination must be on the
same filesystem as the temporary file in that directory, and the filesystem
must support hard links. The utility fails closed if atomic publication is not
available. It does not delete old backups or rotate files automatically.

## Handling the backup

A successful report means SQLite's structural integrity and foreign-key checks
passed. It does not prove that every application-specific receipt/history
ledger is semantically consistent, nor does it prove AOW protocol compatibility.

Treat backups as private game/account data:
- keep the backup directory outside any web root and source repository;
- restrict filesystem permissions and encrypt backups at rest using the
  operator's approved storage mechanism;
- do not upload APKs, captures, credentials, or production database contents
  to this public repository;
- test restore procedures against a separate disposable database before
  relying on a backup.

The utility is standard-library-only and does not connect to any network host.
It is an operational aid for the local synthetic server, not a production
deployment bundle.
