# Synthetic session foundation

`server/sessions.py` implements a local-only session primitive, **not** APK authentication.

- Tokens are generated using `secrets.token_urlsafe(32)`; never log or commit tokens.
- A session maps to an internal account ID and expires according to a monotonic clock.
- `require_character` checks ownership in SQLite before permitting future character actions.
- Revocation and expired-token cleanup are supported; sessions are process-local and disappear on restart.
- No password verification, login HTTP route, real client handshake, transport framing, or AOW packet IDs are implemented.
- The issuing method is for tests or trusted server code only; do not expose it as a public endpoint accepting arbitrary account IDs.
- Before production integration: verified offline client protocol evidence, proper authentication, replay protection, rate limiting, transport security, persistent or distributed session strategy, and authorization on **every** state-changing operation are required.

Run tests using `python -m unittest discover -s tests -v`.
