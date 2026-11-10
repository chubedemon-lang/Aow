# Feature matrix

| Feature | Evidence | Status | Test |
|---|---|---|---|
| Engine | APK manifest/assets and native library inventory identify Unity 6 / IL2CPP; Addressables present | Verified static APK fact | Offline APK inventory |
| Login | LoginRequest/LoginAnswer and serializer identifiers plus native codegen mapping; no wire sequence or credentials verified | Unknown wire contract | Metadata inventory only |
| Character | Synthetic SQLite character domain and separate durable player snapshot store; no APK initialization contract | Synthetic only | Domain and SQLite player-store tests |
| Maps/movement | Synthetic map/position/movement services; no verified APK map-join or movement packets | Synthetic only | Map and movement tests |
| Inventory/shop | Synthetic SQLite inventory/wallet/shop methods; no original item catalog or client route contract | Synthetic only | Ledger and shop tests |
| Combat | Synthetic combat rules and replay validation; no verified AOW combat message contract | Synthetic only | Combat tests |
| Quests | Synthetic quest/reward services; no verified AOW quest schema or progression rules | Synthetic only | Quest tests |
| Sessions | Process-local session manager plus standalone durable SQLite token store; no password auth or APK handshake integration | Primitive only | Session and SQLite session-store tests |
| Deployment | No production deployment bundle; mock HTTP API binds to localhost and must not be exposed | Not ready | CI only |
