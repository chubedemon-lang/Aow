# Verified SQLite online backups

The repository includes `tools.sqlite_backup` for preserving local synthetic
SQLite data before experiments. It is an operational utility only; it does not
make the prototype production-ready or compatible with the unchanged AOW APK.

## Create a backup

Create the destination directory first, then choose a new filename:

```sh
mkdir -p ./backups
python -m tools.sqlite_backup ./var/aow_mock.sqlite3 ./backups/aow_mock-before-change.sqlite3
```

The command:

1. Opens the source through a SQLite read-only URI.
2. Uses SQLite's online backup API, including committed WAL content.
3. Checks the copied database with `PRAGMA quick_check` and
   `PRAGMA foreign_key_check`.
4. Publishes the verified temporary file using an atomic hard link. It never
   replaces an existing destination.
5. Removes the temporary file when backup or publication fails.

The temporary file is created in the destination directory and set to owner-
only permissions on supported platforms. The destination filesystem must
support hard links; otherwise the command fails closed. Do not work around
that failure by copying over an existing database.

## Rehearse a restore

Never restore over a live database. Copy the backup to a new, empty working
path using an operator-controlled restore procedure, then run the appropriate
read-only audit:

- For the base mock schema, use `python -m tools.server_preflight --db PATH
  --host 127.0.0.1 --port 8765`.
- For the extended synthetic inventory/player/map stores, use
  `python -m tools.sqlite_domain_audit --db PATH`.

The base preflight reports `apk_compatible: false` and
`production_ready: false`. A domain audit may report `no_domain_stores` for
the base mock schema; that means those extended stores were not present, not
that the backup failed.

## Safety and scope

- The backup utility does not start a server, open a listener, migrate a schema,
  repair rows, or delete the source.
- It rejects symlink paths, invalid/missing source files, missing destination
  directories, corrupt databases, foreign-key violations and existing
  destinations.
- Its report contains aggregate schema metadata only; it does not dump rows,
  credentials, session tokens or packet bytes.
- Keep databases and backups private and outside this public repository. Never
  commit the APK, extracted assets, player data, credentials or traffic captures.

A successful backup proves only that the local SQLite copy passed its integrity
checks. It does not establish an AOW schema, packet format, authentication
contract, production readiness or APK compatibility.
