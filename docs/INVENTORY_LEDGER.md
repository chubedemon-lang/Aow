# Synthetic inventory ledger

`server/inventory_ledger.py` is an isolated in-memory domain component with per-player item quantities, fixed distinct-item slot limits, stack limits, and atomic grant/consume operations. `tests/test_inventory_ledger.py` covers error paths, player isolation, and mutation safety.

**Not derived from AOW APK.** Item identifiers, limits, inventory structure, persistence, login/session authorization, concurrency, shop prices, equipment, serialization, packet IDs and end-to-end compatibility remain unverified. No client bytes or proprietary assets are stored. Do not expose this ledger as a network endpoint without authentication, persistence/transaction design, and offline protocol evidence.

Run: `python -m unittest discover -s tests -v`.
