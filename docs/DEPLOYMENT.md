# Local synthetic server runbook

**This document covers only the localhost synthetic prototype. It is not a
production deployment guide and does not make the original AOW APK compatible.**

## Scope and hard boundary

The current HTTP API in `server.mock` is a test fixture for Python/SQLite
domain behavior. It has no verified AOW transport, packet framing, handshake,
account authentication, or client-facing message contract. Do not expose it to
the Internet, a LAN, a reverse proxy, or a public VPS. Do not point the original
APK at it and do not use extracted official endpoints.

The runtime now accepts only a literal IPv4 loopback bind address. Hostnames,
wildcard addresses, LAN addresses, and IPv6 are rejected deliberately.

## Requirements

- Python 3.11 or later.
- A local filesystem location for the SQLite database.
- No external Python packages are required.

## Start the synthetic API

From the repository root:

```sh
python -m server.mock --db ./var/aow_mock.sqlite3 --host 127.0.0.1 --port 8765
```

The parent directory must already exist. The server creates the synthetic
schema when it starts. The default bind is loopback and cannot be widened by
passing a non-loopback host.

In another local terminal, check the health endpoint:

```sh
python -c "from urllib.request import urlopen; print(urlopen('http://127.0.0.1:8765/health').read().decode())"
```

The response identifies the service as `synthetic-test-only`. This is not an
APK handshake or login test.

## Read-only database and bind preflight

After the first start has created the database, stop the service or run this
check while it is idle:

```sh
python -m tools.server_preflight --db ./var/aow_mock.sqlite3 --host 127.0.0.1 --port 8765
```

The preflight opens SQLite in read-only mode and checks:

- literal IPv4 loopback binding and a valid TCP port;
- SQLite `quick_check`;
- foreign-key integrity;
- required synthetic column types, nullability, defaults and primary-key layout;
- required unique, foreign-key and CHECK constraints for the synthetic schema.

It does not create, migrate, repair, or modify the database. A successful result
means only that the local synthetic prototype passes these checks. It validates the `synthetic-v1` schema contract. It explicitly reports
`apk_compatible: false` and `production_ready: false`.

## Operational cautions

- Back up the SQLite file before experimenting with synthetic data.
- Keep database files, logs, credentials, APKs, extracted assets and packet
  captures out of Git.
- Do not add password login, bearer-token routes, or public bind options to this
  mock API as a shortcut to APK compatibility.
- Production deployment remains blocked until the real client-facing protocol,
  authentication semantics, server-side authorization model, migrations,
  monitoring, backups and end-to-end tests are established independently.
