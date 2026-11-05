# Synthetic quest award uniqueness

`QuestAwardLedger.grant_quest_once` records a `(player_id, quest_id, item_id)` award key and a request receipt in the same SQLite transaction as the balance increment. Repeating the identical request returns `False`; attempting to use a different request id or payload for the same key raises `RewardConflict` without incrementing the balance. The request id is globally unique.

This is **not an AOW wire protocol** and is not integrated with authenticated sessions, quest completion, item catalog or real inventory. The caller must authorize player ownership, verify quest completion and choose the reward amount on the server. A quest may legitimately award multiple item types, each separately keyed. The ledger does not prevent a separate legacy `SqliteRewardLedger.grant_once` call from granting an unrelated reward, nor does it migrate old receipts into quest keys. Do not use both award paths for the same quest. SQLite must not already be inside a transaction when invoking the method. No production readiness claim.

Run `python -m unittest discover -s tests`.