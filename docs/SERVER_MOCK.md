# Synthetic local server foundation

This minimal Python 3.11+ stdlib-only prototype tests account/character persistence and movement. **It is NOT compatible with the AOW APK**: HTTP JSON endpoints, data models, map ID and coordinates are deliberately invented test fixtures, not reverse-engineered findings.

Run tests: `python -m unittest discover -s tests -p 'test_server_mock.py' -v`

Run server: `python -m server.mock --db aow_mock.sqlite3 --port 8765`

It binds only to `127.0.0.1`. Local test endpoints:
- `GET /health`
- `POST /characters` JSON `{"username":"alice","name":"hero"}`
- `GET /characters/1`
- `POST /characters/1/move` JSON `{"x":25,"y":-10}`

This is not production-ready: no authentication, TLS, rate limiting, network compatibility, anti-cheat, world simulation, or client protocol. Do not expose it publicly. Do not place personal data or proprietary client assets in this repository.

Before implementing the real transport adapter, obtain authorized, redacted evidence of the APK's wire protocol. Keep this synthetic interface separate from any verified protocol implementation.
