# Synthetic quest award uniqueness

`QuestAwardLedger.grant_quest_once` records a `(player_id, quest_id, item_id)` award key and a request receipt in the same SQLite transaction as the balance increment. Repeating the identical request returns `False`; attempting to use a different request id or payload for the same key raises `RewardConflict` without incrementing the balance. The request id is globally unique.

Reward quantities and balances are bounded to SQLite's signed 64-bit INTEGER range. The ledger checks the existing balance inside the same write transaction before crediting it; overflow or a legacy non-integer balance rejects the award and rolls back the quest key and receipt. This protects both the standalone and session-authorized synthetic quest-award facade.

This is **not an AOW wire protocol** and is not integrated with the in-memory inventory/quest adapters, quest completion, item catalog or real inventory. The caller must authorize player ownership, verify quest completion and choose the reward amount on the server. A quest may legitimately award multiple item types, each separately keyed. The ledger does not prevent a separate legacy `SqliteRewardLedger.grant_once` call from granting an unrelated reward, nor does it migrate old receipts into quest keys. Do not use both award paths for the same quest. `grant_quest_once` rejects an already-active connection transaction before issuing any writes, leaving caller-owned work untouched. Invoke it only with an idle connection. No production readiness claim.

Run `python -m unittest discover -s tests`.
