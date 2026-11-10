# Feature matrix

| Feature | Evidence | Status | Test |
|---|---|---|---|
| Engine | APK manifest/assets and native library inventory identify Unity 6 / IL2CPP; Addressables present | Verified static APK fact | Offline APK inventory |
| Login | LoginRequest/LoginAnswer and serializer identifiers plus native codegen mapping; no wire sequence or credentials verified | Unknown wire contract | Metadata inventory only |
| Character | Synthetic SQLite player snapshots now have a session-authorized create/read/apply facade using characters.account_id; no APK initialization contract | Synthetic only | SQLite player-store and authorized-player service tests |
| Maps/movement | Synthetic map/position/movement services plus durable SQLite map-position snapshots; SqliteAuthorizedMapService uses the shared session/character authorizer before every map operation; no verified APK map-join or movement packets | Synthetic only | Map-position and authorized-map service regression tests |
| Inventory/shop | Durable SQLite inventory/player state plus atomic synthetic shop purchase with dual revisions and idempotent receipt; SqliteAuthorizedShopService checks durable session and characters.account_id before each purchase/replay; no original item catalog or client route contract | Synthetic only | SQLite inventory/shop and authorized-shop regression tests |
| Combat | Synthetic combat rules and replay validation; no verified AOW combat message contract | Synthetic only | Combat tests |
| Quests | Synthetic quest/reward services; no verified AOW quest schema or progression rules | Synthetic only | Quest tests |
| Sessions | Process-local session manager plus durable SQLite token store and shared SqliteCharacterAuthorizer; map and player-state facades check session ownership, but no password auth or APK handshake integration | Primitive only | Session, SQLite session-store, authorized-map and authorized-player tests |
| Deployment | No production deployment bundle; mock HTTP API binds to localhost and must not be exposed | Not ready | CI only |
