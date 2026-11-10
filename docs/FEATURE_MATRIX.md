# Feature matrix

| Feature | Evidence | Status | Test |
|---|---|---|---|
| Engine | APK manifest/assets and native library inventory identify Unity 6 / IL2CPP; Addressables present | Verified static APK fact | Offline APK inventory |
| Login | LoginRequest/LoginAnswer and serializer identifiers plus native codegen mapping; no wire sequence or credentials verified | Unknown wire contract | Metadata inventory only |
| Character | Synthetic SQLite player snapshots now have a session-authorized create/read/apply facade using characters.account_id; no APK initialization contract | Synthetic only | SQLite player-store and authorized-player service tests |
| Maps/movement | Synthetic map/position/movement services plus durable SQLite map-position snapshots; SqliteAuthorizedMapService holds BEGIN IMMEDIATE across session resolution, character ownership and every map operation; no verified APK map-join or movement packets | Synthetic only | Map-position and authorized-map service regression tests |
| Inventory/shop | Durable SQLite inventory/player state plus atomic synthetic shop purchase with dual revisions and idempotent receipt; inventory and shop facades hold BEGIN IMMEDIATE across session resolution, character ownership and persistence so revocation cannot race protected operations; no original item catalog or client route contract | Synthetic only | SQLite inventory/shop and authorized inventory/shop regression tests |
| Combat | Deterministic synthetic Battle rules plus session-authorized SQLite battle snapshots, atomic turn/event receipts, optimistic revisions and concurrent idempotency; actor selection is trusted-server-only and no AOW combat contract is known | Synthetic only | Combat and authorized combat persistence tests |
| Quests | Synthetic quest/reward ledgers; SqliteAuthorizedQuestAwardService holds BEGIN IMMEDIATE across session resolution, ownership and reward-ledger reads/grants, but does not verify quest completion or atomically grant into authoritative inventory; no verified AOW quest schema/progression | Synthetic only | Quest-award ledger and authorized quest-award service tests |
| Sessions | Process-local session manager plus durable SQLite token store and shared SqliteCharacterAuthorizer; map, player-state, inventory, shop, quest-award and combat facades check session ownership, but no password auth or APK handshake integration | Primitive only | Session and authorized-domain regression tests |
| Deployment | No production deployment bundle; mock HTTP API binds to localhost and must not be exposed | Not ready | CI only |
